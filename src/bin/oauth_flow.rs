// src/bin/oauth_flow.rs

use anyhow::{anyhow, Context, Result};
use dotenvy::dotenv;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    env,
    io::{self, Write},
};
use urlencoding::encode;

// ---------- Types ----------

#[derive(Debug, Deserialize)]
struct ValuesResp {
    values: Option<Vec<Vec<String>>>,
}

#[derive(Debug, Deserialize)]
struct TokenResp {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
    scope: String,
    token_type: String,
}

// ---------- Main ----------

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok(); // load .env in project root

    // --- config from .env ---
    let client_id = env::var("CLIENT_ID").context("Missing CLIENT_ID")?;
    let client_secret = env::var("CLIENT_SECRET").context("Missing CLIENT_SECRET")?;

    // You can keep using the OOB redirect for this manual flow.
    let redirect_uri = env::var("REDIRECT_URI")
        .unwrap_or_else(|_| "urn:ietf:wg:oauth:2.0:oob".to_string());

    // SCOPES can be comma- or space-separated in .env
    let scopes = env::var("SCOPES").unwrap_or_else(|_| {
        "https://www.googleapis.com/auth/spreadsheets \
         https://www.googleapis.com/auth/drive.file"
            .to_string()
    });

    let input_sheet_id =
        env::var("INPUT_SHEET_ID").context("Set INPUT_SHEET_ID in .env to your input sheet")?;
    let input_range =
        env::var("INPUT_RANGE").unwrap_or_else(|_| "Sheet1!A2:C".to_string());
    let output_title = env::var("OUTPUT_TITLE")
        .unwrap_or_else(|_| "Rust Demo – OAuth Output".to_string());

    // Optional: folder to put the output sheet in (My Drive folder ID)
    // Leave empty / unset to create in root.
    let output_folder_id = env::var("OUTPUT_FOLDER_ID").ok();

    // ---------- OAuth copy-paste flow ----------
    let http = Client::new();
    let bearer = get_access_token_manual(
        &http,
        &client_id,
        &client_secret,
        &redirect_uri,
        &scopes,
    )
    .await?;

    // ---------- Read input sheet ----------
    let input_rows = read_values(&http, &bearer, &input_sheet_id, &input_range).await?;
    println!("Read {} rows from {}", input_rows.len(), input_range);
    preview_rows(&input_rows, 7);

    debug_print_scopes(&http, &bearer).await?;

    // ---------- Aggregate in Rust ----------
    let totals = aggregate_hours_per_worker(&input_rows)?;

    // ---------- Create / reuse output sheet ----------
    let output_id = if let Ok(existing) = env::var("OUTPUT_SHEET_ID") {
        println!("Using existing output sheet: {}", existing);
        existing
    } else {
        create_spreadsheet(
            &http,
            &bearer,
            &output_title,
            output_folder_id.as_deref(), // Option<&str>
        )
        .await?
    };

    println!(
        "Output URL: https://docs.google.com/spreadsheets/d/{}",
        output_id
    );

    // ---------- Build table with formulas ----------
    // A: Worker, B: TotalHours (from Rust), C: ShareOfGrandTotal (formula)
    let mut table: Vec<Vec<String>> = vec![vec![
        "Worker".into(),
        "TotalHours".into(),
        "ShareOfGrandTotal".into(),
    ]];

    for (worker, hours) in &totals {
        table.push(vec![worker.clone(), format!("{}", hours), "".into()]);
    }

    let last_data_row = table.len(); // includes header
    let grand_row = last_data_row + 1;

    // C2..C{n} = share of grand total
    for r in 2..=last_data_row {
        let formula = format!("=B{}/$B${}", r, grand_row);
        if let Some(row) = table.get_mut(r - 1) {
            if row.len() < 3 {
                row.resize(3, "".into());
            }
            row[2] = formula;
        }
    }

    // GRAND TOTAL row
    table.push(vec![
        "GRAND TOTAL".into(),
        format!("=SUM(B2:B{})", last_data_row),
        "".into(),
    ]);

    // ---------- Write values & formulas ----------
    write_values_user_entered(&http, &bearer, &output_id, "Sheet1!A1:C", table).await?;
    println!("Wrote results and formulas.");

    Ok(())
}

// ---------- OAuth helpers ----------

async fn get_access_token_manual(
    http: &Client,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    scopes: &str,
) -> Result<String> {
    // Google expects scopes space-separated
    let scopes_for_url = scopes.replace(',', " ");

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?\
         response_type=code&\
         client_id={}&\
         redirect_uri={}&\
         scope={}&\
         access_type=offline&\
         prompt=consent",
        encode(client_id),
        encode(redirect_uri),
        encode(&scopes_for_url),
    );

    println!("🚀 Open this URL in your browser and log in:\n");
    println!("{auth_url}\n");

    print!("Paste the code here: ");
    io::stdout().flush().ok();
    let mut code = String::new();
    io::stdin().read_line(&mut code)?;
    let code = code.trim();

    if code.is_empty() {
        return Err(anyhow!("No authorization code entered"));
    }

    // Exchange code for tokens
    let params = [
        ("code", code),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
    ];

    let resp = http
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await?
        .error_for_status()?
        .json::<TokenResp>()
        .await?;

    if let Some(ref_token) = &resp.refresh_token {
        println!("Got refresh token (store this if you want to reuse it later).");
        println!("refresh_token={}", ref_token);
    }

    Ok(resp.access_token)
}

// ---------- Sheets / Drive helpers ----------

async fn read_values(
    http: &Client,
    bearer: &str,
    sheet_id: &str,
    range: &str,
) -> Result<Vec<Vec<String>>> {
    let url = format!(
        "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}",
        sheet_id,
        encode(range)
    );

    let resp = http
        .get(&url)
        .bearer_auth(bearer)
        .send()
        .await?
        .error_for_status()?
        .json::<ValuesResp>()
        .await?;

    Ok(resp.values.unwrap_or_default())
}

// Create a Google Spreadsheet using the Drive API, then return its file ID.
// If parent_folder_id is Some, the file is created inside that folder.
async fn create_spreadsheet(
    http: &Client,
    bearer: &str,
    title: &str,
    parent_folder_id: Option<&str>,
) -> Result<String> {
    let url = "https://www.googleapis.com/drive/v3/files?fields=id";

    let body = if let Some(folder_id) = parent_folder_id {
        json!({
            "name": title,
            "mimeType": "application/vnd.google-apps.spreadsheet",
            "parents": [folder_id],
        })
    } else {
        json!({
            "name": title,
            "mimeType": "application/vnd.google-apps.spreadsheet",
        })
    };

    let resp = http
        .post(url)
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        return Err(anyhow!("Drive files.create failed: {} — {}", status, text));
    }

    let v: serde_json::Value = serde_json::from_str(&text)?;
    Ok(v["id"]
        .as_str()
        .context("id missing in files.create response")?
        .to_string())
}

async fn write_values_user_entered(
    http: &Client,
    bearer: &str,
    sheet_id: &str,
    range: &str,
    values: Vec<Vec<String>>,
) -> Result<()> {
    let body = json!({
        "range": range,
        "majorDimension": "ROWS",
        "values": values
    });

    let url = format!(
        "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}?valueInputOption=USER_ENTERED",
        sheet_id,
        encode(range)
    );

    http.put(&url)
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

// ---------- Aggregation + debug helpers ----------

fn aggregate_hours_per_worker(rows: &[Vec<String>]) -> Result<Vec<(String, f64)>> {
    let mut map: BTreeMap<String, f64> = BTreeMap::new();
    for row in rows {
        if row.len() < 3 {
            continue;
        }
        let worker = row[0].trim();
        if worker.is_empty() {
            continue;
        }
        let hours_str = row[2].trim();
        if hours_str.is_empty() {
            continue;
        }
        if let Ok(h) = hours_str.replace(',', ".").parse::<f64>() {
            *map.entry(worker.to_string()).or_default() += h;
        }
    }
    let mut out: Vec<(String, f64)> = map.into_iter().collect();
    out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    Ok(out)
}

/// Pretty-print a few input rows to verify we're reading correctly.
fn preview_rows(rows: &[Vec<String>], max: usize) {
    println!("\n--- Input preview (up to {max} rows) ---");
    println!("{:<12} | {:<10} | {:>5}", "Worker", "Date", "Hours");
    println!("{:-<12}-+-{:-<10}-+-{:-<5}", "", "", "");
    for row in rows.iter().take(max) {
        let w = row.get(0).map(String::as_str).unwrap_or("");
        let d = row.get(1).map(String::as_str).unwrap_or("");
        let h = row.get(2).map(String::as_str).unwrap_or("");
        println!("{:<12} | {:<10} | {:>5}", w, d, h);
    }
    if rows.len() > max {
        println!("… ({} more rows)", rows.len() - max);
    }
    println!("----------------------------------------\n");
}

async fn debug_print_scopes(http: &Client, bearer: &str) -> Result<()> {
    let url = format!(
        "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}",
        bearer
    );
    let txt = http.get(&url).send().await?.text().await?;
    println!("Token info: {txt}");
    Ok(())
}
