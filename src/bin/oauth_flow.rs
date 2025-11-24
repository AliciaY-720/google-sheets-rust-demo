use anyhow::{Context};
use dotenvy::dotenv;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    env,
    fs,
    io::{self, Write},
    path::Path,
};
use urlencoding::encode;

// Where we cache the refresh token.
const REFRESH_TOKEN_PATH: &str = "credentials/refresh_token.txt";

/// ---------- Types ----------

#[derive(Debug, Deserialize)]
struct ValuesResp {
    values: Option<Vec<Vec<String>>>,
}
// #[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TokenResp {
    access_token: String,
    refresh_token: Option<String>,
    // expires_in: i64,
    // scope: String,
    // token_type: String,
}

/// ---------- Main ----------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok(); // load .env

    // --- config from .env ---
    let client_id = env::var("CLIENT_ID").context("Missing CLIENT_ID")?;
    let client_secret = env::var("CLIENT_SECRET").context("Missing CLIENT_SECRET")?;

    let redirect_uri = env::var("REDIRECT_URI")
        // for manual copy-paste we default to out-of-band redirect
        .unwrap_or_else(|_| "urn:ietf:wg:oauth:2.0:oob".to_string());

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
        .unwrap_or_else(|_| "Rust Demo - OAuth Output".to_string());

    // Optional: folder to create the output file in.
    // Leave unset to create in My Drive root.
    let output_folder_id = env::var("OUTPUT_FOLDER_ID").ok();

    let http = reqwest::Client::new();

    // ---------- OAuth with refresh-token cache ----------
    let bearer = get_access_token(
        &http,
        &client_id,
        &client_secret,
        &redirect_uri,
        &scopes,
    )
    .await?;

    // ---------- Read input sheet ----------
    let rows = read_values(&http, &bearer, &input_sheet_id, &input_range).await?;
    println!("Read {} rows from {}", rows.len(), input_range);
    preview_rows(&rows, 7);

    debug_print_scopes(&http, &bearer).await?;

    // ---------- Aggregate in Rust ----------
    let totals = aggregate_hours_per_worker(&rows)?;

    // ---------- Create / reuse output sheet ----------
    let output_id = if let Ok(existing) = env::var("OUTPUT_SHEET_ID") {
        println!("Using existing output sheet: {}", existing);
        existing
    } else {
        create_spreadsheet(&http, &bearer, &output_title, output_folder_id.as_deref()).await?
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

/// ---------- OAuth helpers ----------

/// High-level helper: use refresh token if we have one; otherwise fall back to
/// manual copy-paste and cache the refresh token.
async fn get_access_token(
    http: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    scopes: &str,
) -> anyhow::Result<String> {
    // Try refresh_token from local file first
    if let Ok(contents) = fs::read_to_string(REFRESH_TOKEN_PATH) {
        let refresh_token = contents.trim();
        if !refresh_token.is_empty() {
            match refresh_with_token(http, client_id, client_secret, refresh_token).await {
                Ok(token) => {
                    println!("✅ Used cached refresh token from {}", REFRESH_TOKEN_PATH);
                    return Ok(token);
                }
                Err(e) => {
                    eprintln!("⚠️ Refresh token failed ({e}); falling back to manual login…");
                }
            }
        }
    }

    // No valid refresh token: do full browser flow
    let (access_token, maybe_refresh) =
        get_access_token_manual(http, client_id, client_secret, redirect_uri, scopes).await?;

    // Save refresh token if Google gave us one
    if let Some(rt) = maybe_refresh {
        if !rt.is_empty() {
            if let Some(parent) = Path::new(REFRESH_TOKEN_PATH).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(REFRESH_TOKEN_PATH, &rt)?;
            println!("💾 Saved refresh token to {}", REFRESH_TOKEN_PATH);
        }
    } else {
        println!("(No refresh token returned; you may need to log in again next time.)");
    }

    Ok(access_token)
}

/// Manual browser + copy-paste flow. Returns (access_token, refresh_token).
async fn get_access_token_manual(
    http: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    scopes: &str,
) -> anyhow::Result<(String, Option<String>)> {
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
        println!("Got refresh token; will cache it for next runs.");
        println!("(You don't need to save it manually.)");
        Ok((resp.access_token, Some(ref_token.clone())))
    } else {
        Ok((resp.access_token, None))
    }
}

/// Use the refresh_token to get a new access_token.
async fn refresh_with_token(
    http: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> anyhow::Result<String> {
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("refresh_token", refresh_token),
        ("grant_type", "refresh_token"),
    ];

    let resp = http
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await?
        .error_for_status()?
        .json::<TokenResp>()
        .await?;

    Ok(resp.access_token)
}

/// ---------- Sheets / Drive helpers ----------

async fn read_values(
    http: &reqwest::Client,
    bearer: &str,
    sheet_id: &str,
    range: &str,
) -> anyhow::Result<Vec<Vec<String>>> {
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
// If parent_folder_id is Some(id), the file is created inside that folder.
async fn create_spreadsheet(
    http: &reqwest::Client,
    bearer: &str,
    title: &str,
    parent_folder_id: Option<&str>,
) -> anyhow::Result<String> {
    let url = "https://www.googleapis.com/drive/v3/files?fields=id";

    let mut body = json!({
        "name": title,
        "mimeType": "application/vnd.google-apps.spreadsheet",
    });

    if let Some(folder_id) = parent_folder_id {
        body["parents"] = json!([folder_id]);
    }

    let resp = http
        .post(url)
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        anyhow::bail!("Drive files.create failed: {} — {}", status, text);
    }

    let v: serde_json::Value = serde_json::from_str(&text)?;
    Ok(v["id"]
        .as_str()
        .context("id missing in files.create response")?
        .to_string())
}

async fn write_values_user_entered(
    http: &reqwest::Client,
    bearer: &str,
    sheet_id: &str,
    range: &str,
    values: Vec<Vec<String>>,
) -> anyhow::Result<()> {
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

/// ---------- Aggregation + debug helpers ----------

fn aggregate_hours_per_worker(rows: &[Vec<String>]) -> anyhow::Result<Vec<(String, f64)>> {
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

async fn debug_print_scopes(http: &reqwest::Client, bearer: &str) -> anyhow::Result<()> {
    let url = format!(
        "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}",
        bearer
    );
    let txt = http.get(&url).send().await?.text().await?;
    println!("Token info: {txt}");
    Ok(())
}
