use super::{WebAuthnContract, WebAuthnContractExt};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use near_sdk::{env, log, near, CryptoHash};
use serde_json::json;

// Simple test structures for yield-resume testing
#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct TestYieldData {
    pub message: String,
    pub value: i32,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct TestCompletionData {
    pub key: String,
    pub description: String,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct RawData1 {
    pub raw_data1: String,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct RawData2 {
    pub raw_data2: String,
}



/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

const DATA_ID_REGISTER: u64 = 0;

#[near]
impl WebAuthnContract {

    pub fn yield_test(&self) -> String {
        env::log_str("calling yield_test");


        let yield_promise = env::promise_yield_create(
            "callback_test",
            // serde_json::json!({ "raw_data1": "YIELDING" }).to_string().into_bytes().as_slice(),
            &serde_json::to_vec(&RawData1 { raw_data1: "YIELDING STRUCT".to_string() }).expect("Failed to serialize RawData1"),
            near_sdk::Gas::from_tgas(10),
            near_sdk::GasWeight::default(),
            DATA_ID_REGISTER,
        );


        // Read the yield_resume_id from the register after yield creation
        let yield_resume_id_bytes = env::read_register(DATA_ID_REGISTER)
            .expect("Failed to read yield_resume_id from register after yield creation");
        let yield_resume_id_b64url = BASE64_URL_ENGINE.encode(&yield_resume_id_bytes);

        // // return the yield promise (not needed? not actually returned)
        env::promise_return(yield_promise);

        env::log_str(&format!("yield_test: yield created with resume_id: {}", yield_resume_id_b64url));
        yield_resume_id_b64url
    }

    #[private]
    pub fn callback_test(
        &mut self,
        raw_data1: String,                      // argument from promise_yield_create()
        #[callback_unwrap] raw_data2: RawData2, // argument from promise_yield_resume()
    ) -> String {

        let count = env::promise_results_count();

        let greeting = format!("Total: {}, first: {}, second: {:?}", count, raw_data1, raw_data2);
        self.set_greeting(greeting);

        env::log_str("CALLBACK_TEST: Successfully executed and returning");
        "CALLBACK RESULT".to_string()
    }

    pub fn resume_test(
        &self,
        yield_resume_id: String,
    ) -> bool {

        // Decode the base64url encoded yield_resume_id
        let yield_resume_id_bytes = match BASE64_URL_ENGINE.decode(&yield_resume_id) {
            Ok(bytes) => bytes,
            Err(e) => {
                env::log_str(&format!("Failed to decode yield_resume_id: {}", e));
                return false;
            }
        };

        // Convert to CryptoHash
        let data_id: CryptoHash = match yield_resume_id_bytes.try_into() {
            Ok(hash) => hash,
            Err(_) => {
                env::log_str("Failed to convert yield_resume_id to CryptoHash");
                return false;
            }
        };

        env::log_str(&format!("resume_test with data_id: {:?}", data_id));

        // Resume execution with empty data (just to trigger the callback)
        env::promise_yield_resume(
            &data_id,
            serde_json::json!({ "raw_data2": "RESUMING" }).to_string().into_bytes().as_slice(),
        );

        true
    }

}
