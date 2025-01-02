//server.js
require("dotenv").config();
const mysql = require("mysql2");
const express = require("express");
const { userSchema } = require("./validation");
const app = express();
const bcrypt = require("bcryptjs"); 
const jwt = require("jsonwebtoken");
const authenticateJWT = require("./middleware/auth"); 
const AppError = require("./utils/errors");
const errorHandler = require("./middleware/errorHandler");
const cors = require("cors");
app.use(cors());

const corsOptions = {
  origin: "http://localhost:3001", //3001 for example
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true, 
};

app.use(cors(corsOptions));

app.use(express.json()); 

app.get("/public", (req, res) => {
  res.send("This is a public route.");
});


app.get("/profile", authenticateJWT, (req, res) => {
  
  res.json({
    message: "User profile",
    user: req.user, 
  });
});

app.get("/users/:id", (req, res, next) => {
  const { id } = req.params;

  connection.query("SELECT * FROM users WHERE id = ?", [id], (err, results) => {
    if (err) return next(new AppError(500, "Error getting user", err));

    if (results.length === 0) {
      return next(new AppError(404, "User not found"));
    }

    res.status(200).json(results[0]);
  });
});

app.use(errorHandler);
//contact database
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err.stack);
    return;
  }
  console.log("Connected to MySQL with connection ID" + connection.threadId);
});

app.post("/login", (req, res, next) => {
  const { email, password } = req.body;

  const query = "SELECT id, name, email, password FROM users WHERE email = ?";
  connection.query(query, [email], (err, results) => {
    if (err) return next(new AppError(500, "Error verifying user"));

    if (results.length === 0) {
      return next(new AppError(404, "User not found"));
    }

    const user = results[0];
    const isPasswordValid = bcrypt.compareSync(password, user.password);

    if (!isPasswordValid) {
      return next(new AppError(401, "Incorrect password"));
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ token });
  });
});


function handleError(res, err, message) {
  console.error(message, err);
  res.status(500).send(message || "Error in the database");
}
//Create users
app.post("/users", (req, res) => {
  const { error } = userSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  const { name, email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10); 

  const query = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
  connection.query(query, [name, email, hashedPassword], (err, results) => {
    if (err) {
      return handleError(res, err, "Error creating user");
    }
    res.status(201).send({ id: results.insertId, name, email });
  });
});

//Get users
app.get("/users", (req, res) => {
  const query = "SELECT id, name, email FROM users"; 
  connection.query(query, (err, results) => {
    if (err) {
      return handleError(res, err, "Error getting users");
    }
    res.status(200).json(results);
  });
});

// Get users by id
app.get("/users/:id", (req, res) => {
  const { id } = req.params;
  const query = "SELECT id, name, email FROM users WHERE id = ?";
  connection.query(query, [id], (err, results) => {
    if (err) {
      return handleError(res, err, "Error getting user");
    }
    if (results.length === 0) {
      return res.status(404).send("User not found");
    }
    res.status(200).json(results[0]);
  });
});

// Update users
app.put("/users/:id", (req, res) => {
  const { id } = req.params;
  const { name, email, password } = req.body;

  const { error } = userSchema.validate({ name, email, password });
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  const hashedPassword = bcrypt.hashSync(password, 10); 

  const query =
    "UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?";
  connection.query(query, [name, email, hashedPassword, id], (err, results) => {
    if (err) {
      return handleError(res, err, "Error updating user");
    }
    if (results.affectedRows === 0) {
      return res.status(404).send("User not found");
    }
    res.status(200).send("Updated user");
  });
});

// Delete user
app.delete("/users/:id", (req, res) => {
  const { id } = req.params;
  const query = "DELETE FROM users WHERE id = ?";
  connection.query(query, [id], (err, results) => {
    if (err) {
      return handleError(res, err, "Error deleting user");
    }
    if (results.affectedRows === 0) {
      return res.status(404).send("User not found");
    }
    res.status(200).send("User deleted");
  });
});

// Start the server 
app.listen(process.env.PORT, () => {
  console.log(`Server running on port: ${process.env.PORT}`);
});
