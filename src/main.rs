use std::collections::HashMap;
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
use egui::{Window, RichText, Color32};
use sha2::{Sha256, Digest};
use rfd::FileDialog;

enum AppState {
    FileDialog,
    //Main,
}

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

    fn encrypt_password(password: &str, key: &str) -> String {
        let key = derive_key(key);
        let key = GenericArray::from_slice(&key);
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

    fn decrypt_password(encoded: &str, key: &str) -> String {
        let key = derive_key(key);
        let key = GenericArray::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let decoded = general_purpose::STANDARD.decode(encoded).expect("Decoding failed");
        let (nonce, ciphertext) = decoded.split_at(12);

        let nonce_array = GenericArray::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce_array, ciphertext)
            .expect("decryption failure!");

        String::from_utf8(plaintext).expect("Invalid UTF-8")
    }

    fn add_entry(&mut self, web: String, usuario: String, contraseña: String, adicional: String, key: &str) {
        let encrypted_password = Self::encrypt_password(&contraseña, key);
        self.entries.push(PasswordEntry {
            web,
            usuario,
            contraseña: encrypted_password,
            adicional,
        });
    }
}


struct MyApp {
    password_manager: PasswordManager,
    show_add_window: bool,
    new_entry: PasswordEntry,
    show_passwords: HashMap<usize, bool>,
    key: String,
    key_set: bool,
    file_path: Option<String>,
    show_file_dialog: bool,
    state: AppState,
}

impl MyApp {
    fn new() -> Self {
        MyApp {
            password_manager: PasswordManager::new(),
            show_add_window: false,
            new_entry: PasswordEntry {
                web: String::new(),
                usuario: String::new(),
                contraseña: String::new(),
                adicional: String::new(),
            },
            show_passwords: HashMap::new(),
            key: String::new(),
            key_set: false,
            file_path: None,
            show_file_dialog: true,
            state: AppState::FileDialog,
        }
    }

    fn open_file_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("Selecciona un archivo de contraseñas")
            .pick_file()
        {
            self.file_path = Some(path.to_string_lossy().to_string());
            self.password_manager = PasswordManager::load_from_file(&self.file_path.as_ref().unwrap());
            self.show_file_dialog = false;
        }
    }

    fn save_file_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("Guardar archivo de contraseñas")
            .save_file()
        {
            self.file_path = Some(path.to_string_lossy().to_string());
            self.password_manager.save_to_file(&self.file_path.as_ref().unwrap());
        }
    }

    fn add_new_entry(&mut self) {
        let web = self.new_entry.web.clone();
        let usuario = self.new_entry.usuario.clone();
        let contraseña = self.new_entry.contraseña.clone();
        let adicional = self.new_entry.adicional.clone();

        self.password_manager.add_entry(web, usuario, contraseña, adicional, self.key.as_str());
        //self.password_manager.save_to_file("passwords.json");
        if let Some(ref path) = self.file_path {
            self.password_manager.save_to_file(path);
        }

        self.new_entry = PasswordEntry {
            web: String::new(),
            usuario: String::new(),
            contraseña: String::new(),
            adicional: String::new(),
        };
        self.show_add_window = false;
    }

    fn show_file_dialog_ui(&mut self, ctx: &Context) {
        Window::new("Seleccionar archivo")
            .open(&mut matches!(self.state, AppState::FileDialog))
            .show(ctx, |ui| {
                if ui.button("Abrir archivo existente").clicked() {
                    self.open_file_dialog();
                }
                if ui.button("Crear nuevo archivo").clicked() {
                    self.save_file_dialog();
                }
            });
    }

    fn show_main_ui(&mut self, ctx: &Context) {
        if !self.key_set {
            Window::new("Introduce la clave")
                .open(&mut true)
                .show(ctx, |ui| {
                    ui.label("Clave:");
                    if ui.text_edit_singleline(&mut self.key).lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.key_set = true;
                    }
                });
        } else {
            CentralPanel::default().show(ctx, |ui| {
                ui.heading("Password Manager");

                if !self.password_manager.entries.is_empty() {
                    egui::Grid::new("password_grid")
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label(RichText::new("Web").color(Color32::WHITE).size(20.0)).highlight();
                            ui.label(RichText::new("Usuario").color(Color32::WHITE).size(20.0)).highlight();
                            ui.label(RichText::new("Contraseña").color(Color32::WHITE).size(20.0)).highlight();
                            ui.label(RichText::new("View").color(Color32::WHITE).size(20.0)).highlight();
                            ui.label(RichText::new("Adicional").color(Color32::WHITE).size(20.0)).highlight();
                            ui.end_row();

                            for (index, entry) in self.password_manager.entries.iter().enumerate() {
                                let mut is_visible = self.show_passwords.get(&index).cloned().unwrap_or(false);
                                ui.label(&entry.web);
                                ui.label(&entry.usuario);

                                if is_visible {
                                    ui.label(&PasswordManager::decrypt_password(&entry.contraseña, self.key.as_str()));
                                } else {
                                    ui.label("********");
                                }
                                if ui.checkbox(&mut is_visible, "").clicked() {
                                    self.show_passwords.insert(index, is_visible);
                                }

                                ui.label(split_text(&entry.adicional, 5));
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