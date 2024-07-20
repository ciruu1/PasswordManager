use aes_gcm::aead::{Aead, KeyInit, OsRng, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm}; // Or `Aes128Gcm`
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use aes_gcm::aead::rand_core::RngCore;
use eframe::App;
use eframe::egui::{self, CentralPanel, Context};
use egui::Window;

const KEY: &[u8] = b"an example very very secret key."; // 32 bytes for AES-256

#[derive(Serialize, Deserialize, Debug)]
struct PasswordEntry {
    web: String,
    usuario: String,
    contraseña: String,
    adicional: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PasswordManager {
    entries: Vec<PasswordEntry>,
}

impl PasswordManager {
    fn new() -> Self {
        PasswordManager { entries: Vec::new() }
    }

    fn load_from_file(file_path: &str) -> Self {
        if Path::new(file_path).exists() {
            let mut file = File::open(file_path).expect("Unable to open file");
            let mut data = String::new();
            file.read_to_string(&mut data).expect("Unable to read file");
            serde_json::from_str(&data).expect("Unable to parse JSON")
        } else {
            let manager = PasswordManager::new();
            manager.save_to_file(file_path);
            manager
        }
    }

    fn save_to_file(&self, file_path: &str) {
        let data = serde_json::to_string_pretty(self).expect("Unable to serialize JSON");
        let mut file = File::create(file_path).expect("Unable to create file");
        file.write_all(data.as_bytes()).expect("Unable to write to file");
    }

    fn encrypt_password(password: &str) -> String {
        let key = GenericArray::from_slice(KEY);
        let cipher = Aes256Gcm::new(key);

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let nonce_array = GenericArray::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_array, password.as_bytes())
            .expect("encryption failure!");

        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);

        general_purpose::STANDARD.encode(&result)
    }

    fn decrypt_password(encoded: &str) -> String {
        let key = GenericArray::from_slice(KEY);
        let cipher = Aes256Gcm::new(key);

        let decoded = general_purpose::STANDARD.decode(encoded).expect("Decoding failed");
        let (nonce, ciphertext) = decoded.split_at(12);

        let nonce_array = GenericArray::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce_array, ciphertext)
            .expect("decryption failure!");

        String::from_utf8(plaintext).expect("Invalid UTF-8")
    }

    fn add_entry(&mut self, web: String, usuario: String, contraseña: String, adicional: String) {
        let encrypted_password = Self::encrypt_password(&contraseña);
        self.entries.push(PasswordEntry {
            web,
            usuario,
            contraseña: encrypted_password,
            adicional,
        });
    }

    fn get_entries(&self) -> Vec<PasswordEntry> {
        self.entries
            .iter()
            .map(|entry| PasswordEntry {
                web: entry.web.clone(),
                usuario: entry.usuario.clone(),
                contraseña: Self::decrypt_password(&entry.contraseña),
                adicional: entry.adicional.clone(),
            })
            .collect()
    }
}


struct MyApp {
    password_manager: PasswordManager,
    show_add_window: bool,
    new_entry: PasswordEntry,
}

impl MyApp {
    fn new() -> Self {
        let file_path = "passwords.json";
        let password_manager = PasswordManager::load_from_file(file_path);

        MyApp {
            password_manager,
            show_add_window: false,
            new_entry: PasswordEntry {
                web: String::new(),
                usuario: String::new(),
                contraseña: String::new(),
                adicional: String::new(),
            },
        }
    }

    fn add_new_entry(&mut self) {
        let web = self.new_entry.web.clone();
        let usuario = self.new_entry.usuario.clone();
        let contraseña = self.new_entry.contraseña.clone();
        let adicional = self.new_entry.adicional.clone();

        self.password_manager.add_entry(web, usuario, contraseña, adicional);
        self.password_manager.save_to_file("passwords.json");

        self.new_entry = PasswordEntry {
            web: String::new(),
            usuario: String::new(),
            contraseña: String::new(),
            adicional: String::new(),
        };
        self.show_add_window = false;
    }
}

impl App for MyApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        CentralPanel::default().show(ctx, |ui| {
            ui.heading("Password Manager");

            if !self.password_manager.entries.is_empty() {
                egui::Grid::new("password_grid")
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("Web");
                        ui.label("Usuario");
                        ui.label("Contraseña");
                        ui.label("Adicional");
                        ui.end_row();

                        for entry in self.password_manager.get_entries() {
                            ui.label(&entry.web);
                            ui.label(&entry.usuario);
                            ui.label(&entry.contraseña);
                            ui.label(&entry.adicional);
                            ui.end_row();
                        }
                    });
            } else {
                ui.label("No hay contraseñas guardadas.");
            }

            if ui.button("Añadir entrada").clicked() {
                self.show_add_window = true;
            }
        });

        let mut show_add_window = self.show_add_window;
        Window::new("Añadir nueva entrada")
            .open(&mut show_add_window)
            .show(ctx, |ui| {
                ui.label("Web:");
                ui.text_edit_singleline(&mut self.new_entry.web);
                ui.label("Usuario:");
                ui.text_edit_singleline(&mut self.new_entry.usuario);
                ui.label("Contraseña:");
                ui.text_edit_singleline(&mut self.new_entry.contraseña);
                ui.label("Adicional:");
                ui.text_edit_singleline(&mut self.new_entry.adicional);

                if ui.button("Guardar").clicked() {
                    self.add_new_entry();
                }
            });
        self.show_add_window = show_add_window;
    }
}

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Password Manager",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::new()) as Box<dyn App>)),
    ).expect("Failed to run the app");
}