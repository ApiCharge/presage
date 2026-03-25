use presage::Manager;
use presage::model::identity::OnNewIdentity;
use presage_store_sqlite::SqliteStore;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db_url = std::env::var("PRESAGE_DB_PATH")?;
    println!("Opening store at {db_url}...");

    let store = SqliteStore::open(&db_url, OnNewIdentity::Trust).await?;
    println!("Store opened successfully");

    println!("Loading registered manager...");
    match Manager::load_registered(store).await {
        Ok(manager) => {
            let reg = manager.registration_data();
            println!("SUCCESS! Phone: {}, UUID: {}", reg.phone_number, reg.service_ids.aci);
        }
        Err(e) => {
            println!("FAILED: {e:#}");
        }
    }
    Ok(())
}
