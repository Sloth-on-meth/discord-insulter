use anyhow::Result;
use reqwest;

/// Summarize a user's message history using OpenAI.
pub async fn summarize_history(openai_token: &str, user_name: &str, history: &str) -> Result<String> {
    let prompt = format!(
        "Summarize the following Discord user's message history in 3-5 bullet points. Focus on recurring topics, personality traits, running jokes, and any memorable quirks or behaviors. Do NOT include sensitive or private info.\n\nUser: {}\nHistory:\n{}",
        user_name, history
    );
    let messages = vec![
        serde_json::json!({ "role": "system", "content": "You are a Discord bot assistant. Summarize user history for efficient, context-aware humor." }),
        serde_json::json!({ "role": "user", "content": prompt }),
    ];
    let client = reqwest::Client::new();
    let res = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(openai_token)
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "messages": messages,
            "max_tokens": 200,
            "temperature": 0.3
        }))
        .send()
        .await?;
    let res_json: serde_json::Value = res.json().await?;
    if let Some(choice) = res_json.get("choices").and_then(|c| c.as_array()).and_then(|arr| arr.get(0)) {
        if let Some(message) = choice.get("message").and_then(|m| m.get("content")) {
            if let Some(summary) = message.as_str() {
                return Ok(summary.trim().to_string());
            }
        }
    }
    Ok("No summary available.".to_string())
}
