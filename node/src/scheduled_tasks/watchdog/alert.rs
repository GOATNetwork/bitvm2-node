use super::monitor::{AlertType, LivenessAlert};
use reqwest::Client;
use serde_json::json;
use tracing::warn;

pub struct AlertConfig {
    pub webhook_url: Option<String>,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub pagerduty_routing_key: Option<String>,
}

impl AlertConfig {
    pub fn from_env() -> Self {
        Self {
            webhook_url: std::env::var("WATCHDOG_WEBHOOK_URL").ok(),
            telegram_bot_token: std::env::var("WATCHDOG_TELEGRAM_TOKEN").ok(),
            telegram_chat_id: std::env::var("WATCHDOG_TELEGRAM_CHAT_ID").ok(),
            pagerduty_routing_key: std::env::var("WATCHDOG_PAGERDUTY_KEY").ok(),
        }
    }

}

pub async fn dispatch_alerts(alerts: Vec<LivenessAlert>, config: &AlertConfig) {
    for alert in &alerts {
        let msg = format_alert_message(alert);

        if let Some(url) = &config.webhook_url {
            send_webhook(url, &msg).await;
        }
        if let (Some(token), Some(chat_id)) = (&config.telegram_bot_token, &config.telegram_chat_id)
        {
            send_telegram(token, chat_id, &msg).await;
        }
        if let Some(key) = &config.pagerduty_routing_key {
            send_pagerduty(key, alert).await;
        }
    }
}

fn format_alert_message(a: &LivenessAlert) -> String {
    let kind = match a.alert_type {
        AlertType::AssertInitMissing => "AssertInitMissing",
        AlertType::AssertCommitStall => "AssertCommitStall",
    };
    format!(
        "[GOAT Watchdog] Challenger Liveness Alert\n\
         Type: {kind}\n\
         Instance: {}\n\
         Graph: {}\n\
         Kickoff TX: {}\n\
         Blocks Until Timeout: {}\n\
         Action Required: Check challenger node immediately!",
        a.instance_id, a.graph_id, a.kickoff_txid, a.blocks_until_timeout
    )
}

async fn send_webhook(url: &str, message: &str) {
    let client = Client::new();
    if let Err(e) = client.post(url).json(&json!({ "text": message })).send().await {
        warn!("watchdog: webhook send failed: {e}");
    }
}

async fn send_telegram(token: &str, chat_id: &str, message: &str) {
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let client = Client::new();
    if let Err(e) =
        client.post(&url).json(&json!({ "chat_id": chat_id, "text": message })).send().await
    {
        warn!("watchdog: telegram send failed: {e}");
    }
}

async fn send_pagerduty(routing_key: &str, alert: &LivenessAlert) {
    let kind = match alert.alert_type {
        AlertType::AssertInitMissing => "AssertInitMissing",
        AlertType::AssertCommitStall => "AssertCommitStall",
    };
    let client = Client::new();
    if let Err(e) = client
        .post("https://events.pagerduty.com/v2/enqueue")
        .json(&json!({
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": format!("Challenger offline - {kind}"),
                "severity": "critical",
                "source": "goat-bitvm2-watchdog",
                "custom_details": {
                    "graph_id": alert.graph_id.to_string(),
                    "kickoff_txid": alert.kickoff_txid,
                    "blocks_until_timeout": alert.blocks_until_timeout,
                }
            }
        }))
        .send()
        .await
    {
        warn!("watchdog: pagerduty send failed: {e}");
    }
}
