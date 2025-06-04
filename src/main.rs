use serenity::async_trait;
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::prelude::*;
use serde::Deserialize;
use std::fs;
use anyhow::Result;

#[derive(Deserialize)]
struct Config {
    discord_token: String,
    openai_token: String,
    insult_channel_id: String,
}

struct Handler {
    config: Config,
}

#[async_trait]
impl EventHandler for Handler {
    async fn message(&self, ctx: Context, msg: Message) {
        // Only insult in the configured channel, and ignore bots
        if msg.channel_id.to_string() != self.config.insult_channel_id || msg.author.bot {
            return;
        }
        // Don't insult yourself
        if msg.mentions_me(&ctx.http).await.unwrap_or(false) {
            return;
        }

        let insult = match get_insult(&self.config.openai_token, &msg.author.name).await {
            Ok(insult) => insult,
            Err(_) => "Couldn't think of an insult right now!".to_string(),
        };
        let _ = msg.channel_id.say(&ctx.http, insult).await;
    }

    async fn ready(&self, _: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config: Config = serde_json::from_str(&fs::read_to_string("config.json")?)?;
    let handler = Handler { config };
    let mut client = Client::builder(&handler.config.discord_token, GatewayIntents::all())
        .event_handler(handler)
        .await?;
    client.start().await?;
    Ok(())
}

async fn get_insult(openai_token: &str, username: &str) -> Result<String> {
    let prompt = format!("Insult {} in a creative and funny way.", username);
    let client = reqwest::Client::new();
    let res = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(openai_token)
        .json(&serde_json::json!({
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": "You are a witty AI that only gives creative, funny, and non-offensive insults."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 60
        }))
        .send()
        .await?;
    let json: serde_json::Value = res.json().await?;
    Ok(json["choices"][0]["message"]["content"].as_str().unwrap_or("You are not worth insulting!").to_string())
}
