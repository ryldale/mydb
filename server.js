const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const axios = require("axios");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const session = require("express-session");

require("dotenv").config();

const app = express();
app.use(express.json());

app.use(
  cors({
    origin: "https://food-recipes-self.vercel.app",
    methods: ["GET", "POST", "DELETE", "PUT"],
    credentials: true,
  })
);

app.use(
  session({
    secret: process.env.SESSION_SECRET_KEY,
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000,
      sameSite: "None",
    },
  })
);

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// REGISTER
app.post("/api/users/register", async (req, res) => {
  const { first_name, last_name, email, country, password } = req.body;
  if (!first_name || !last_name || !email || !country || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
  db.execute(checkEmailQuery, [email], (err, results) => {
    if (err) {
      console.error("Error checking email:", err);
      return res.status(500).json({ message: "Error checking email" });
    }

    if (results.length > 0) {
      return res.status(400).json({ message: "Email is already in use" });
    }

    const saltRounds = 10;
    bcrypt.hash(password, saltRounds, (err, passwordHash) => {
      if (err) {
        console.error("Error hashing password:", err);
        return res.status(500).json({ message: "Error registering user" });
      }

      const query = `
        INSERT INTO users (first_name, last_name, email, password_hash, country, created_at)
        VALUES (?, ?, ?, ?, ?, NOW())
      `;

      db.execute(
        query,
        [first_name, last_name, email, passwordHash, country],
        (err, results) => {
          if (err) {
            console.error("Error registering user:", err);
            return res.status(500).json({ message: "Error registering user" });
          }
          res.status(200).json({ message: "User registered successfully" });
        }
      );
    });
  });
});

// LOGIN
app.post("/api/users/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  const query = "SELECT * FROM users WHERE email = ?";

  db.execute(query, [email], (err, results) => {
    if (err) {
      console.error("Error fetching user:", err);
      return res.status(500).json({ message: "Error logging in" });
    }

    if (results.length === 0) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const user = results[0];

    bcrypt.compare(password, user.password_hash, (err, isMatch) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        return res.status(500).json({ message: "Error logging in" });
      }

      if (!isMatch) {
        return res.status(400).json({ message: "Invalid email or password" });
      }

      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET_KEY, {
        expiresIn: "1h",
      });

      req.session.token = token;

      res.status(200).json({
        message: "Login successful",
        token: token,
        user: {
          id: user.id,
          first_name: user.first_name,
          last_name: user.last_name,
          email: user.email,
          country: user.country,
        },
      });
    });
  });
});

// REST COUNTRIES
app.get("/api/countries", async (req, res) => {
  try {
    const response = await axios.get("https://restcountries.com/v3.1/all");

    const countries = response.data.map((country) => ({
      name: country.name.common,
    }));

    countries.sort((a, b) => a.name.localeCompare(b.name));

    res.status(200).json(countries);
  } catch (err) {
    console.error("Error fetching countries:", err);
    res.status(500).json({ message: "Error fetching countries" });
  }
});

// Middleware to verify JWT and extract user ID
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  

  if (!token) {
    return res.status(403).json({ message: "Token is required" });
  }

  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    req.userId = decoded.userId;
    next();
  });
};

// CREATE user-specific data
app.post("/api/users/data/create", verifyToken, (req, res) => {
  const { food_name, food_recipe } = req.body;

  if (!food_name || !food_recipe) {
    return res.status(400).json({ message: "Data is required" });
  }

  const query = `
    INSERT INTO user_data (user_id, food_name, food_recipe, created_at)
    VALUES (?, ?, ?, NOW())
  `;

  db.execute(query, [req.userId, food_name, food_recipe], (err, results) => {
    if (err) {
      console.error("Error storing data:", err);
      return res.status(500).json({ message: "Error storing data" });
    }
    res
      .status(200)
      .json({ message: "Data stored successfully", dataId: results.insertId });
  });
});

// READ user-specific data
app.get("/api/users/data", verifyToken, (req, res) => {
  const query = `
    SELECT * FROM user_data WHERE user_id = ?
  `;

  db.execute(query, [req.userId], (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      return res.status(500).json({ message: "Error fetching data" });
    }

    res.status(200).json(results);
  });
});

// DELETE user-specific data
app.delete("/api/users/data/delete/:id", verifyToken, (req, res) => {
  const dataId = req.params.id;

  const checkQuery = "SELECT * FROM user_data WHERE id = ? AND user_id = ?";
  db.execute(checkQuery, [dataId, req.userId], (err, results) => {
    if (err) {
      console.error("Error checking data:", err);
      return res.status(500).json({ message: "Error checking data" });
    }

    if (results.length === 0) {
      return res
        .status(404)
        .json({ message: "Data not found or not authorized to delete" });
    }

    // Proceed with deletion
    const deleteQuery = "DELETE FROM user_data WHERE id = ?";
    db.execute(deleteQuery, [dataId], (err, results) => {
      if (err) {
        console.error("Error deleting data:", err);
        return res.status(500).json({ message: "Error deleting data" });
      }

      res.status(200).json({ message: "Data deleted successfully" });
    });
  });
});

// Define the /api/users/profile endpoint
app.get("/api/users/profile", verifyToken, (req, res) => {
  const query =
    "SELECT first_name, last_name, email, country FROM users WHERE id = ?";

  db.execute(query, [req.userId], (err, results) => {
    if (err) {
      console.error("Error fetching user data:", err);
      return res.status(500).json({ message: "Error fetching user data" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = results[0];
    res.status(200).json({
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      country: user.country,
    });
  });
});

// UPDATE user profile
app.put("/api/users/update", verifyToken, (req, res) => {
  const {
    first_name,
    last_name,
    email,
    country,
    current_password,
    new_password,
    confirm_new_password,
  } = req.body;

  if (!first_name && !last_name && !email && !country && !new_password) {
    return res.status(400).json({ message: "No data to update" });
  }

  if (email && !validator.isEmail(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  if (new_password && !current_password) {
    return res.status(400).json({ message: "Current password is required" });
  }

  if (
    new_password &&
    typeof new_password === "string" &&
    typeof confirm_new_password === "string" &&
    new_password.trim() !== confirm_new_password.trim()
  ) {
    return res.status(400).json({ message: "New passwords do not match" });
  }

  if (current_password) {
    db.execute(
      "SELECT password_hash FROM users WHERE id = ?",
      [req.userId],
      (err, results) => {
        if (err)
          return res
            .status(500)
            .json({ message: "Error retrieving user data" });
        if (results.length === 0)
          return res.status(404).json({ message: "User not found" });

        bcrypt.compare(
          current_password,
          results[0].password_hash,
          (err, isMatch) => {
            if (err)
              return res
                .status(500)
                .json({ message: "Error checking password" });
            if (!isMatch)
              return res
                .status(400)
                .json({ message: "Incorrect current password" });

            let updateQuery = "UPDATE users SET ";
            let updateValues = [];

            if (first_name) {
              updateQuery += "first_name = ?, ";
              updateValues.push(first_name);
            }
            if (last_name) {
              updateQuery += "last_name = ?, ";
              updateValues.push(last_name);
            }
            if (email) {
              updateQuery += "email = ?, ";
              updateValues.push(email);
            }
            if (country) {
              updateQuery += "country = ?, ";
              updateValues.push(country);
            }

            if (new_password) {
              bcrypt.hash(new_password, 10, (err, hashedNewPassword) => {
                if (err)
                  return res
                    .status(500)
                    .json({ message: "Error hashing new password" });
                updateQuery += "password_hash = ?, ";
                updateValues.push(hashedNewPassword);
                executeUpdateQuery();
              });
            } else {
              executeUpdateQuery();
            }

            function executeUpdateQuery() {
              updateQuery = updateQuery.slice(0, -2) + " WHERE id = ?";
              updateValues.push(req.userId);
              db.execute(updateQuery, updateValues, (err) => {
                if (err)
                  return res
                    .status(500)
                    .json({ message: "Error updating profile" });
                res
                  .status(200)
                  .json({ message: "Profile updated successfully" });
              });
            }
          }
        );
      }
    );
  } else {
    let updateQuery = "UPDATE users SET ";
    let updateValues = [];

    if (first_name) {
      updateQuery += "first_name = ?, ";
      updateValues.push(first_name);
    }
    if (last_name) {
      updateQuery += "last_name = ?, ";
      updateValues.push(last_name);
    }
    if (email) {
      updateQuery += "email = ?, ";
      updateValues.push(email);
    }
    if (country) {
      updateQuery += "country = ?, ";
      updateValues.push(country);
    }

    updateQuery = updateQuery.slice(0, -2) + " WHERE id = ?";
    updateValues.push(req.userId);

    db.execute(updateQuery, updateValues, (err) => {
      if (err)
        return res.status(500).json({ message: "Error updating profile" });
      res.status(200).json({ message: "Profile updated successfully" });
    });
  }
});

// UPDATE user-specific food data (edit food name and recipe)
app.put("/api/users/data/update/:id", verifyToken, (req, res) => {
  const dataId = req.params.id; // Recipe ID
  const { food_name, food_recipe } = req.body;

  if (!food_name || !food_recipe) {
    return res
      .status(400)
      .json({ message: "Food name and recipe are required" });
  }

  // Check if the data exists and if the user owns it
  const checkQuery = "SELECT * FROM user_data WHERE id = ? AND user_id = ?";
  db.execute(checkQuery, [dataId, req.userId], (err, results) => {
    if (err) {
      console.error("Error checking data:", err);
      return res.status(500).json({ message: "Error checking data" });
    }

    if (results.length === 0) {
      return res
        .status(404)
        .json({ message: "Data not found or not authorized to edit" });
    }

    // Proceed with update
    const updateQuery = `
      UPDATE user_data 
      SET food_name = ?, food_recipe = ? 
      WHERE id = ? AND user_id = ?
    `;
    db.execute(
      updateQuery,
      [food_name, food_recipe, dataId, req.userId],
      (err, results) => {
        if (err) {
          console.error("Error updating data:", err);
          return res.status(500).json({ message: "Error updating data" });
        }

        res.status(200).json({ message: "Data updated successfully" });
      }
    );
  });
});

const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
