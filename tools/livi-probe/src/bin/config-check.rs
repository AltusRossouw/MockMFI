// SPDX-FileCopyrightText: 2026 MockMFI contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Parse a generated LIVI config.json with LIVI's own Config type, so a setup
// script cannot silently write a key that LIVI does not understand.
use livi_core_proto::config::{defaults, Config};

fn main() {
    let path = std::env::args().nth(1).expect("usage: config-check <config.json> | --default");
    if path == "--default" {
        let text = serde_json::to_string_pretty(&defaults()).expect("serialize defaults");
        println!("{text}");
        return;
    }
    let text = std::fs::read_to_string(&path).expect("read config");
    match serde_json::from_str::<Config>(&text) {
        Ok(c) => {
            println!("valid=true");
            println!("carName={}", c.car_name);
            println!("wirelessCpEnabled={}", c.wireless_cp_enabled);
            println!("wirelessAaEnabled={}", c.wireless_aa_enabled);
            println!("wifiInterface={}", c.wifi_interface);
            println!("wifiType={:?}", c.wifi_type);
            println!("wifiChannel={}", c.wifi_channel);
            println!("wifiChannelWidth={}", c.wifi_channel_width);
            println!("wifiPasswordLen={}", c.wifi_password.len());
            println!("btAdapter={}", c.bt_adapter);
            println!("mfiI2cBus={}", c.car_play_mfi_i2c_bus);
        }
        Err(e) => {
            eprintln!("valid=false error={e}");
            std::process::exit(1);
        }
    }
}
