use anyhow::Result;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use std::fs::File;
use std::io::Write;
use uuid::Uuid;

/// Calls OpenAI TTS API to synthesize speech from text, saves to /tmp, and returns the file path.
pub async fn tts_to_file(openai_token: &str, text: &str) -> Result<String> {
    let url = "https://api.openai.com/v1/audio/speech";
    let voice = "alloy"; // default OpenAI voice
    let output_format = "mp3";
    let filename = format!("/tmp/tts-{}.mp3", Uuid::new_v4());
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "model": "tts-1",
        "input": text,
        "voice": voice,
        "response_format": output_format,
        "speed": 1.0
    });
    let resp = client
        .post(url)
        .header(AUTHORIZATION, format!("Bearer {}", openai_token))
        .header(CONTENT_TYPE, "application/json")
        .json(&payload)
        .send()
        .await?;
    let bytes = resp.bytes().await?;
    let mut file = File::create(&filename)?;
    file.write_all(&bytes)?;
    Ok(filename)
}
