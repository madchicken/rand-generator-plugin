use falco_plugin::anyhow::{anyhow, Error};
use falco_plugin::async_event::{AsyncEvent, AsyncEventPlugin, AsyncHandler};
use falco_plugin::base::{Json, Plugin};
use falco_plugin::event::events::types::{EventType};
use falco_plugin::event::events::{Event, EventMetadata};
use falco_plugin::extract::{field, EventInput, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::schemars::JsonSchema;
use falco_plugin::serde::Deserialize;
use falco_plugin::source::{PluginEvent};
use falco_plugin::tables::TablesInput;
use falco_plugin::{
    async_event_plugin, extract_plugin, parse_plugin, plugin,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::BTreeMap;
use std::ffi::{CStr};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn};

pub struct RandomGenPlugin {
    /// Specifies the range within witch the random
    /// value is generated. The range must be set
    /// from the plugin configuration.
    range: u64,

    /// Keep track of all numbers generated with how
    /// many times each one occurred
    histogram: Arc<Mutex<BTreeMap<u64, u64>>>,

    /// Random number generator
    thread_range: Arc<Mutex<StdRng>>,
}

#[derive(JsonSchema, Deserialize)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(crate = "falco_plugin::serde")]
pub struct Config {
    /// Defines the random generator range.
    range: u64,
}

/// Plugin metadata
impl Plugin for RandomGenPlugin {
    const NAME: &'static CStr = c"random_generator";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"generates a continuous stream of random numbers";
    const CONTACT: &'static CStr = c"https://github.com/falcosecurity/plugin-sdk-rs";
    type ConfigType = Json<Config>;

    fn new(_input: Option<&TablesInput>, Json(config): Self::ConfigType) -> Result<Self, Error> {
        Ok(Self {
            range: config.range,
            histogram: Arc::new(Mutex::new(BTreeMap::new())),
            thread_range: Arc::new(Mutex::new(StdRng::from_entropy())),
        })
    }

    fn set_config(&mut self, _config: Self::ConfigType) -> Result<(), Error> {
        Ok(())
    }
}

impl AsyncEventPlugin for RandomGenPlugin {
    const ASYNC_EVENTS: &'static [&'static str] = &["random_number"]; // generate any async events
    const EVENT_SOURCES: &'static [&'static str] = &[]; // attach to all event sources

    // This is useful when we have a background mechanism to generate the events.
    // In this example we're not doing that.
    // The SDK provides a helper, you may want to check it:
    // https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/async_event/struct.BackgroundTask.html
    fn start_async(&mut self, handler: AsyncHandler) -> Result<(), Error> {
        let rng = self.thread_range.clone();
        let range = self.range;
        spawn(move || loop {
            let num: u64 = rng.lock().unwrap().gen_range(0..range);
            let event = num.to_le_bytes().to_vec();
            let event = AsyncEvent {
                plugin_id: Some(1234),
                name: Some(c"random_number"),
                data: Some(&event),
            };
            let metadata = EventMetadata::default();
            let event = Event {
                metadata,
                params: event,
            };
            match handler.emit(event) {
                Ok(_) => {
                    println!("Async event emitted {}", num);
                }
                Err(e) => {
                    eprintln!("Error emitting async event: {:?}", e);
                }
            }
            sleep(std::time::Duration::from_secs(1));
        });
        Ok(())
    }

    fn stop_async(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl RandomGenPlugin {
    /// Reads the raw event payload and converts it to u64 value.
    fn extract_number(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event = req.event.event()?;
        let async_event = event.load::<AsyncEvent>()?;
        let buf = async_event.params.data.ok_or_else(|| anyhow!("Missing event data"))?;
        Ok(u64::from_le_bytes(buf.try_into()?))
    }

    fn extract_count(&mut self, _req: ExtractRequest<Self>, num: u64) -> Result<u64, Error> {
        // Get the count of occurrences of `num` from `self.histogram`.
        // If the number isn't there (hasn't been generated even once),
        // return zero
        if let Ok(guard) = self.histogram.lock() {
            match guard.get(&num) {
                Some(count) => Ok(*count),
                None => Ok(0),
            }
        } else {
            Ok(0)
        }
    }
}

/// Event Parsing Capability
impl ParsePlugin for RandomGenPlugin {
    const EVENT_TYPES: &'static [EventType] = &[EventType::ASYNCEVENT_E]; // inspect all events...
    const EVENT_SOURCES: &'static [&'static str] = &[]; // ... from this plugin's source

    fn parse_event(&mut self, event: &EventInput, _parse_input: &ParseInput) -> Result<(), Error> {
        let event = event.event()?;
        let async_event = event.load::<AsyncEvent>()?;
        let buf = async_event.params.data.ok_or_else(|| anyhow!("Missing event data"))?;

        let num = u64::from_le_bytes(buf.try_into()?);

        // increase the number of occurrences of `num` in the histogram
        if let Ok(mut guard) = self.histogram.lock() {
            println!("Parsed event: {}", num);
            *guard.entry(num).or_insert(0) += 1;
        }

        Ok(())
    }
}

/// Implement the field extraction capability
/// https://falco.org/docs/plugins/architecture/#field-extraction-capability
/// https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/extract/trait.ExtractPlugin.html
///
/// This trait exposes a set of items that need to be satisifed
///
/// # The set of event types supported by this plugin
/// If empty, the plugin will get invoked for all event types, otherwise it will only
/// get invoked for event types from this list.
///
/// # The set of event sources supported by this plugin
/// If empty, the plugin will get invoked for events coming from all sources, otherwise it will
/// only get invoked for events from sources named in this list.
///
/// # The extraction context
/// # The actual list of extractable fields
impl ExtractPlugin for RandomGenPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &["random_generator"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("gen.num", &Self::extract_number),
        field("gen.count", &Self::extract_count),
    ];
}

plugin!(RandomGenPlugin);
extract_plugin!(RandomGenPlugin);
parse_plugin!(RandomGenPlugin);
async_event_plugin!(RandomGenPlugin);
