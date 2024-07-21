#![windows_subsystem = "windows"]

use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use aes_gcm::aead::{Aead, generic_array::GenericArray, KeyInit, OsRng};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::Aes256Gcm;
use base64::{Engine as _, engine::general_purpose};
use csv::ReaderBuilder;
use eframe::App;
use eframe::egui::{self, CentralPanel, Context};
use egui::{Color32, RichText, Window};
use egui_extras::{Column, TableBuilder};
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

enum AppState {
    FileDialog,
    //Main,
}

#[derive(Serialize, Deserialize, Debug)]
struct PasswordEntry {
    web_name: String,
    web: String,
    user: String,
    password: String,
    additional: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PasswordManager {
    entries: Vec<PasswordEntry>,
}

impl PasswordManager {
    fn new() -> Self {
        PasswordManager { entries: Vec::new() }
    }

    fn load_from_file(file_path: &str, key: &str) -> Self {
        if Path::new(file_path).exists() {
            let mut file = File::open(file_path).expect("Unable to open file");
            let mut data = String::new();
            file.read_to_string(&mut data).expect("Unable to read file");
            let decrypted_data = Self::decrypt_data(data.as_str(), key);
            serde_json::from_str(&decrypted_data).expect("Unable to parse JSON")
        } else {
            let manager = PasswordManager::new();
            manager.save_to_file(file_path, key);
            manager
        }
    }

    fn save_to_file(&self, file_path: &str, key: &str) {
        let data = serde_json::to_string_pretty(self).expect("Unable to serialize JSON");
        let encrypted_data = Self::encrypt_data(data.as_str(), key);
        let mut file = File::create(file_path).expect("Unable to create file");
        file.write_all(encrypted_data.as_bytes()).expect("Unable to write to file");
    }

    fn encrypt_data(data: &str, key: &str) -> String {
        let key = derive_key(key);
        let key = GenericArray::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let nonce_array = GenericArray::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_array, data.as_bytes())
            .expect("Encryption failure!");

        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);

        general_purpose::STANDARD.encode(&result)
    }

    fn decrypt_data(encoded: &str, key: &str) -> String {
        let key = derive_key(key);
        let key = GenericArray::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let decoded = general_purpose::STANDARD.decode(encoded).expect("Decoding failed");
        let (nonce, ciphertext) = decoded.split_at(12);

        let nonce_array = GenericArray::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce_array, ciphertext)
            .expect("Decryption failure!");

        String::from_utf8(plaintext).expect("Invalid UTF-8")
    }

    fn add_entry(&mut self, web_name: String, web: String, usuario: String, password: String, adicional: String, key: &str) {
        let encrypted_password = Self::encrypt_data(&password, key);
        self.entries.push(PasswordEntry {
            web_name,
            web,
            user: usuario,
            password: encrypted_password,
            additional: adicional,
        });
    }

    fn update_entry(&mut self, index: usize, web_name: String, web: String, user: String, password: String, additional: String, key: &str) {
        if let Some(entry) = self.entries.get_mut(index) {
            entry.web_name = web_name;
            entry.web = web;
            entry.user = user;
            entry.password = Self::encrypt_data(&password, key);
            entry.additional = additional;
        }
    }

    fn load_from_csv(file_path: &str, key: &str) -> Result<Self, Box<dyn Error>> {
        let mut rdr = ReaderBuilder::new().from_path(file_path)?;
        let mut manager = PasswordManager::new();

        for result in rdr.records() {
            let record = result?;
            let web_name = record.get(0).unwrap_or("").to_string();
            let web = record.get(1).unwrap_or("").to_string();
            let user = record.get(2).unwrap_or("").to_string();
            let password = record.get(3).unwrap_or("").to_string();
            let additional = record.get(4).unwrap_or("").to_string();

            manager.add_entry(web_name, web, user, password, additional, key);
        }

        Ok(manager)
    }
}


struct MyApp {
    password_manager: PasswordManager,
    show_add_window: bool,
    show_edit_window: Option<usize>,
    new_entry: PasswordEntry,
    edit_entry: PasswordEntry,
    show_passwords: HashMap<usize, bool>,
    key: String,
    key_set: bool,
    file_path: Option<String>,
    show_file_dialog: bool,
    state: AppState,
    search_query: String,
}

impl MyApp {
    fn new() -> Self {
        MyApp {
            password_manager: PasswordManager::new(),
            show_add_window: false,
            show_edit_window: None,
            new_entry: PasswordEntry {
                web_name: String::new(),
                web: String::new(),
                user: String::new(),
                password: String::new(),
                additional: String::new(),
            },
            edit_entry: PasswordEntry {
                web_name: String::new(),
                web: String::new(),
                user: String::new(),
                password: String::new(),
                additional: String::new(),
            },
            show_passwords: HashMap::new(),
            key: String::new(),
            key_set: false,
            file_path: None,
            show_file_dialog: true,
            state: AppState::FileDialog,
            search_query: String::new(),
        }
    }

    fn open_file_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("Select a password file")
            .pick_file()
        {
            self.file_path = Some(path.to_string_lossy().to_string());
            self.password_manager = PasswordManager::load_from_file(&self.file_path.as_ref().unwrap(), self.key.as_str());
            self.show_file_dialog = false;
        }
    }

    fn save_file_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("Save the password file")
            .save_file()
        {
            self.file_path = Some(path.to_string_lossy().to_string());
            self.password_manager.save_to_file(&self.file_path.as_ref().unwrap(), self.key.as_str());
        }
    }

    fn add_new_entry(&mut self) {
        let web_name = self.new_entry.web_name.clone();
        let web = self.new_entry.web.clone();
        let user = self.new_entry.user.clone();
        let password = self.new_entry.password.clone();
        let additional = self.new_entry.additional.clone();

        self.password_manager.add_entry(web_name, web, user, password, additional, self.key.as_str());
        //self.password_manager.save_to_file("passwords.json");
        if let Some(ref path) = self.file_path {
            self.password_manager.save_to_file(path, self.key.as_str());
        }

        self.new_entry = PasswordEntry {
            web_name: String::new(),
            web: String::new(),
            user: String::new(),
            password: String::new(),
            additional: String::new(),
        };
        self.show_add_window = false;
    }

    fn edit_entry(&mut self, index: usize) {
        if let Some(entry) = self.password_manager.entries.get(index) {
            self.edit_entry.web_name = entry.web_name.clone();
            self.edit_entry.web = entry.web.clone();
            self.edit_entry.user = entry.user.clone();
            self.edit_entry.password = PasswordManager::decrypt_data(entry.password.clone().as_str(), self.key.as_str());
            self.edit_entry.additional = entry.additional.clone();
            self.show_edit_window = Some(index);
        }
    }

    fn save_edited_entry(&mut self, index: usize) {
        let web_name = self.edit_entry.web_name.clone();
        let web = self.edit_entry.web.clone();
        let user = self.edit_entry.user.clone();
        let password = self.edit_entry.password.clone();
        let additional = self.edit_entry.additional.clone();

        self.password_manager.update_entry(index, web_name, web, user, password, additional, self.key.as_str());
        if let Some(ref path) = self.file_path {
            self.password_manager.save_to_file(path, self.key.as_str());
        }

        self.show_edit_window = None;
    }

    fn import_from_csv(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("Select a CSV file")
            .pick_file()
        {
            let result = PasswordManager::load_from_csv(path.to_string_lossy().to_string().as_str(), self.key.as_str());
            match result {
                Ok(manager) => {
                    self.password_manager.entries.extend(manager.entries);
                    if let Some(ref file_path) = self.file_path {
                        self.password_manager.save_to_file(file_path, self.key.as_str());
                    }
                }
                Err(e) => {
                    eprintln!("Error importing from CSV: {}", e);
                }
            }
        }
    }

    fn show_file_dialog_ui(&mut self, ctx: &Context) {
        if !self.key_set {
            Window::new("Enter the password")
                .open(&mut true)
                .show(ctx, |ui| {
                    ui.label("Password:");
                    if ui.add(egui::TextEdit::singleline(&mut self.key).password(true)).lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.key_set = true;
                    }
                });
        } else {
            Window::new("Select file")
                .open(&mut matches!(self.state, AppState::FileDialog))
                .show(ctx, |ui| {
                    if ui.button("Open existing file").clicked() {
                        self.open_file_dialog();
                    }
                    if ui.button("Create new file").clicked() {
                        self.save_file_dialog();
                    }
                });
        }
    }

    fn show_main_ui(&mut self, ctx: &Context) {
        let mut edit_index: Option<usize> = None;

        CentralPanel::default().show(ctx, |ui| {
            ui.heading(RichText::new("Password Manager").color(Color32::WHITE).size(30.0));

            if ui.button("Add new entry").highlight().clicked() {
                self.show_add_window = true;
            }

            if ui.button("Import from CSV").on_hover_text("Make sure that the file uses\nchrome structure for passwords").clicked() {  // Añadir este botón
                self.import_from_csv();
            }

            ui.horizontal(|ui| {
                ui.label("Search:");
                ui.text_edit_singleline(&mut self.search_query);
            });

            let available_height = ui.available_height();

            egui::ScrollArea::both()
                .show(ui, |ui| {
                    if !self.password_manager.entries.is_empty() {
                        TableBuilder::new(ui)
                            .column(Column::remainder().at_least(50.0).clip(true).resizable(true))
                            .column(Column::remainder().at_least(50.0).clip(true).resizable(true))
                            .column(Column::remainder().at_least(50.0).clip(true).resizable(true))
                            .column(Column::initial(100.0).at_least(50.0))
                            .column(Column::initial(50.0).at_least(50.0))
                            .column(Column::remainder().at_least(50.0).clip(true).resizable(true))
                            .column(Column::initial(50.0).at_least(50.0))
                            .striped(true)
                            .resizable(true)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .min_scrolled_height(0.0)
                            .max_scroll_height(available_height)
                            .header(20.0, |mut header| {
                                header.col(|ui| {
                                    ui.heading("Web Name");
                                });
                                header.col(|ui| {
                                    ui.heading("URL");
                                });
                                header.col(|ui| {
                                    ui.heading("User");
                                });
                                header.col(|ui| {
                                    ui.heading("Password");
                                });
                                header.col(|ui| {
                                    ui.heading("View");
                                });
                                header.col(|ui| {
                                    ui.heading("Additional");
                                });
                                header.col(|ui| {
                                    ui.heading("Edit");
                                });
                            })
                            .body(|mut body| {
                                for (index, entry) in self.password_manager.entries.iter().enumerate() {
                                    if !self.search_query.is_empty() &&
                                        !entry.web_name.to_lowercase().contains(&self.search_query.to_lowercase()) &&
                                        !entry.web.to_lowercase().contains(&self.search_query.to_lowercase()) &&
                                        !entry.user.to_lowercase().contains(&self.search_query.to_lowercase()) &&
                                        !entry.additional.to_lowercase().contains(&self.search_query.to_lowercase()) {
                                        continue;
                                    }

                                    let mut is_visible = self.show_passwords.get(&index).cloned().unwrap_or(false);

                                    body.row(20.0, |mut row| {
                                        row.col(|ui| {
                                            ui.label(&entry.web_name);
                                        });
                                        row.col(|ui| {
                                            ui.label(&entry.web);
                                        });
                                        row.col(|ui| {
                                            ui.label(&entry.user);
                                        });

                                        row.col(|ui| {
                                            if is_visible {
                                                ui.label(&PasswordManager::decrypt_data(&entry.password, self.key.as_str()));
                                            } else {
                                                ui.label("********");
                                            }
                                        });
                                        row.col(|ui| {
                                            ui.centered_and_justified(|ui| {
                                                if ui.checkbox(&mut is_visible, "").clicked() {
                                                    self.show_passwords.insert(index, is_visible);
                                                }
                                            });
                                        });

                                        row.col(|ui| {
                                            ui.label(split_text(&entry.additional, 5));
                                        });

                                        row.col(|ui| {
                                            ui.centered_and_justified(|ui| {
                                                if ui.button("Edit").clicked() {
                                                    edit_index = Some(index);
                                                }
                                            });
                                        });

                                    });
                                }
                            });
                    } else {
                        ui.label("There are no passwords stored.");
                    }
                });
        });

        if let Some(index) = edit_index {
            self.edit_entry(index);
        }

        let mut show_add_window = self.show_add_window;
        Window::new("Add a new entry")
            .open(&mut show_add_window)
            .show(ctx, |ui| {
                ui.label("Web Name:");
                ui.text_edit_singleline(&mut self.new_entry.web_name);
                ui.label("URL:");
                ui.text_edit_singleline(&mut self.new_entry.web);
                ui.label("User:");
                ui.text_edit_singleline(&mut self.new_entry.user);
                ui.label("Password:");
                ui.text_edit_singleline(&mut self.new_entry.password);
                ui.label("Additional info:");
                ui.text_edit_singleline(&mut self.new_entry.additional);

                if ui.button("Save").clicked() {
                    self.add_new_entry();
                }
            });
        self.show_add_window = show_add_window;

        if let Some(index) = self.show_edit_window {
            Window::new("Edit entry")
                .open(&mut true)
                .show(ctx, |ui| {
                    ui.label("Web Name:");
                    ui.text_edit_singleline(&mut self.edit_entry.web_name);
                    ui.label("URL:");
                    ui.text_edit_singleline(&mut self.edit_entry.web);
                    ui.label("User:");
                    ui.text_edit_singleline(&mut self.edit_entry.user);
                    ui.label("Password:");
                    ui.text_edit_singleline(&mut self.edit_entry.password);
                    ui.label("Additional info:");
                    ui.text_edit_singleline(&mut self.edit_entry.additional);

                    if ui.button("Save").clicked() {
                        self.save_edited_entry(index);
                    }
                });
        }
    }
}

impl App for MyApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if self.show_file_dialog {
            self.show_file_dialog_ui(ctx);
        } else {
            self.show_main_ui(ctx);
        }
    }
}

fn split_text(text: &String, max_words_per_line: usize) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut result = String::new();
    let mut current_line = String::new();
    let mut word_count = 0;

    for word in words {
        if word_count >= max_words_per_line {
            result.push_str(&current_line.trim_end());
            result.push('\n');
            current_line.clear();
            word_count = 0;
        }
        current_line.push_str(word);
        current_line.push(' ');
        word_count += 1;
    }

    if !current_line.is_empty() {
        result.push_str(&current_line.trim_end());
    }

    result
}

// Función para derivar una clave de 32 bytes a partir de una clave proporcionada por el usuario
fn derive_key(user_key: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(user_key);
    hasher.finalize().to_vec()
}

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Password Manager",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::new()) as Box<dyn App>)),
    ).expect("Failed to run the app");
}