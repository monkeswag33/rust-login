// use std::{
//     env,
//     fs::OpenOptions,
//     io::{BufRead, BufReader},
// };

// mod methods;

use argon2::{self, Config};
use diesel::prelude::*;
use inquire::{Confirm, Password, PasswordDisplayMode, Select, Text};
use login_rust::*;
use models::*;
use ring::rand::{self, SecureRandom};

struct Program {
    logged_in: bool,
    user: Option<User>,
    pg_con: PgConnection,
}
const SALT_LEN: usize = 16;

impl Default for Program {
    fn default() -> Program {
        Program {
            logged_in: false,
            user: None,
            pg_con: establish_connection(),
        }
    }
}

impl Program {
    fn gen_salt(&self) -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        let rng = rand::SystemRandom::new();
        rng.fill(&mut salt).expect("Could not generate salt");
        return salt;
    }

    fn gen_hash(&self, password: &str) -> String {
        let salt: [u8; SALT_LEN] = self.gen_salt();
        let hash = argon2::hash_encoded(password.as_bytes(), &salt, &Config::default())
            .expect("Could not generate hash");
        return hash;
    }

    fn signup(&mut self) {
        use diesel::prelude::*;
        use login_rust::schema::users;
        let username = Text::new("Username:").prompt().unwrap();
        let password = Password::new("Password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .prompt()
            .unwrap();
        let hash = self.gen_hash(&password);
        let new_user = NewUser {
            username: &username,
            password: &hash,
        };
        // Insert new user
        let inserted_user: models::User = diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(&self.pg_con)
            .expect("Error saving new post");
        self.logged_in = true;
        self.user = Some(inserted_user);
    }

    fn login(&mut self) {
        use schema::users::dsl::{username, users};
        let target_username = Text::new("Username:").prompt().unwrap();
        let target_password = Password::new("Password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .prompt()
            .unwrap();

        let users_retreived = users
            .filter(username.eq(&target_username))
            .load::<User>(&self.pg_con)
            .expect("Error getting user");
        if users_retreived.len() != 1 {
            return println!("User not found...");
        }
        let user = users_retreived[0].clone();
        let matches = argon2::verify_encoded(&user.password, target_password.as_bytes())
            .expect("Error verifying password");
        if matches {
            self.logged_in = true;
            self.user = Some(user);
            return println!("Successfully logged in");
        } else {
            return println!("Password is incorrect...");
        }
    }

    fn change_username(&mut self) {
        use schema::users::dsl::{username, users};
        let new_username = Text::new("New username:").prompt().unwrap();
        let target_id = self.user.as_ref().unwrap().id;
        let updated_user = diesel::update(users.find(target_id))
            .set(username.eq(new_username))
            .get_result::<User>(&self.pg_con)
            .expect(&format!("Unable to find user {}", target_id));
        self.user = Some(updated_user);
    }

    fn change_password(&mut self) {
        use schema::users::dsl::{password, users};
        let new_password = Password::new("New password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .prompt()
            .unwrap();
        let target_id = self.user.as_ref().unwrap().id;
        let updated_user = diesel::update(users.find(target_id))
            .set(password.eq(self.gen_hash(&new_password)))
            .get_result::<User>(&self.pg_con)
            .expect(&format!("Unable to find user {}", target_id));
        self.user = Some(updated_user);
    }

    fn delete_user(&mut self) {
        use schema::users::dsl::users;
        let confirmation = Confirm::new("Are you sure you want to delete this account (y/n)?")
            .prompt()
            .unwrap();
        if confirmation == false {
            return;
        }
        let num_deleted = diesel::delete(users.find(self.user.as_ref().unwrap().id))
            .execute(&self.pg_con)
            .expect("Error deleting posts");
        println!("{}", num_deleted);
        self.logged_in = false;
        self.user = None;
    }

    fn logout(&mut self) {
        self.logged_in = false;
        self.user = None;
    }

    pub fn start(&mut self) {
        let login_signup = vec!["Login", "Signup", "Quit"];
        let logged_in = vec![
            "Change Username",
            "Change Password",
            "Logout",
            "Delete User",
        ];
        loop {
            if !self.logged_in {
                let ans = Select::new("What do you want to do?", login_signup.clone())
                    .prompt()
                    .unwrap();
                match ans {
                    "Signup" => self.signup(),
                    "Login" => self.login(),
                    "Quit" => break,
                    _ => {}
                }
            } else {
                let ans = Select::new("What do you want to do?", logged_in.clone())
                    .prompt()
                    .unwrap();
                match ans {
                    "Change Username" => self.change_username(),
                    "Change Password" => self.change_password(),
                    "Logout" => self.logout(),
                    "Delete User" => self.delete_user(),
                    _ => {}
                }
            }
        }
    }
}

fn main() {
    let mut prog = Program {
        ..Default::default()
    };
    prog.start();
}
