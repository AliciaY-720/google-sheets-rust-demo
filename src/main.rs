use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use urlencoding::encode;
use yup_oauth2::{ServiceAccountAuthenticator, ServiceAccountKey};

#[derive(Debug, Deserialize)]
struct ValuesResp {
    values: Option<Vec<Vec<String>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // --- config from env ---
    let input_sheet_id = env::var("INPUT_SHEET_ID")
        .context("Set INPUT_SHEET_ID to your input spreadsheet ID")?;
    let input_range = env::var("INPUT_RANGE").unwrap_or_else(|_| "Sheet1!A2:C".to_string());
    let output_title =
        env::var("OUTPUT_TITLE").unwrap_or_else(|_| "Rust Demo – Aggregation Output".to_string());

    // --- auth (service account) ---
    let sa_key_path =
        env::var("GOOGLE_APPLICATION_CREDENTIALS").unwrap_or_else(|_| "service-account.json".into());
    let token = get_token(&sa_key_path, &[
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]).await?;
    let bearer = token.as_str().to_owned();
    let http = Client::new();

    // --- read input ---
    let input_rows = read_values(&http, &bearer, &input_sheet_id, &input_range).await?;
    println!("Read {} rows from {}", input_rows.len(), input_range);

    // --- aggregate in Rust ---
    // Expect rows like: [Worker, Date, Hours]
    let totals = aggregate_hours_per_worker(&input_rows)?;

    // --- create output spreadsheet ---
    let output_id = create_spreadsheet(&http, &bearer, &output_title).await?;
    println!("Output URL: https://docs.google.com/spreadsheets/d/{}", output_id);

    // --- prepare table with formulas ---
    // A: Worker, B: TotalHours (from Rust), C: ShareOfGrandTotal (formula)
    let mut table: Vec<Vec<String>> = vec![vec![
        "Worker".into(),
        "TotalHours".into(),
        "ShareOfGrandTotal".into(),
    ]];
    for (worker, hours) in &totals {
        table.push(vec![worker.clone(), format!("{}", hours), "".into()]);
    }
    let last_data_row = table.len();           // includes header
    let grand_row = last_data_row + 1;         // where we'll put SUM

    for r in 2..=last_data_row {
        let formula = format!("=B{}/$B${}", r, grand_row);
        if let Some(row) = table.get_mut(r - 1) {
            if row.len() < 3 { row.resize(3, "".into()); }
            row[2] = formula;
        }
    }
    table.push(vec!["GRAND TOTAL".into(), format!("=SUM(B2:B{})", last_data_row), "".into()]);

    // --- write values & formulas (USER_ENTERED) ---
    write_values_user_entered(&http, &bearer, &output_id, "Sheet1!A1:C", table).await?;
    println!("Wrote results and formulas.");

    // OPTIONAL: share the new file back to your user account so it appears in Drive
    if let Ok(your_email) = env::var("SHARE_WITH_EMAIL") {
        share_to_user(&http, &bearer, &output_id, &your_email).await?;
        println!("Shared output to {}", your_email);
    }

    Ok(())
}

async fn get_token(sa_key_path: &str, scopes: &[&str]) -> Result<yup_oauth2::AccessToken> {
    let sa_key: ServiceAccountKey = ServiceAccountKey::from_file(sa_key_path)
        .with_context(|| format!("Failed to read {sa_key_path}"))?;
    let auth = ServiceAccountAuthenticator::builder(sa_key).build().await?;
    Ok(auth.token(scopes).await?)
}

async fn read_values(http: &Client, bearer: &str, sheet_id: &str, range: &str)
    -> Result<Vec<Vec<String>>>
{
    let url = format!(
        "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}",
        sheet_id, encode(range)
    );
    let resp = http.get(&url)
        .bearer_auth(bearer)
        .send().await?
        .error_for_status()?
        .json::<ValuesResp>().await?;
    Ok(resp.values.unwrap_or_default())
}

async fn create_spreadsheet(http: &Client, bearer: &str, title: &str) -> Result<String> {
    let body = json!({ "properties": { "title": title } });
    let created: serde_json::Value = http
        .post("https://sheets.googleapis.com/v4/spreadsheets")
        .bearer_auth(bearer)
        .json(&body)
        .send().await?
        .error_for_status()?
        .json().await?;
    Ok(created["spreadsheetId"]
        .as_str()
        .context("spreadsheetId missing")?
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
        sheet_id, encode(range)
    );
    http.put(&url)
        .bearer_auth(bearer)
        .json(&body)
        .send().await?
        .error_for_status()?;
    Ok(())
}

async fn share_to_user(http: &Client, bearer: &str, file_id: &str, email: &str) -> Result<()> {
    let url = format!(
        "https://www.googleapis.com/drive/v3/files/{}/permissions?sendNotificationEmail=false",
        file_id
    );
    let body = json!({ "role":"writer", "type":"user", "emailAddress": email });
    http.post(&url)
        .bearer_auth(bearer)
        .json(&body)
        .send().await?
        .error_for_status()?;
    Ok(())
}

fn aggregate_hours_per_worker(rows: &[Vec<String>]) -> Result<Vec<(String, f64)>> {
    let mut map: BTreeMap<String, f64> = BTreeMap::new();
    for row in rows {
        if row.len() < 3 { continue; }
        let worker = row[0].trim();
        if worker.is_empty() { continue; }
        let hours_str = row[2].trim();
        if hours_str.is_empty() { continue; }
        if let Ok(h) = hours_str.replace(',', ".").parse::<f64>() {
            *map.entry(worker.to_string()).or_default() += h;
        }
    }
    let mut out: Vec<(String, f64)> = map.into_iter().collect();
    out.sort_by(|a,b| b.1.partial_cmp(&a.1).unwrap());
    Ok(out)
}
