const express = require("express");
require("dotenv").config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();

app.use(express.json());

// Ensure the uploads directory exists
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Directory to save uploaded files
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const filename = file.fieldname + "-" + Date.now() + ext;
    cb(null, filename);
  },
});

const upload = multer({ storage: storage });

// LOCAL DB
const users = [];

// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user;
    next();
  });
};

// Middleware for role-based access control
const authorizeRole = (requiredRole) => {
  return (req, res, next) => {
    if (req.user.role !== requiredRole) {
      return res.status(403).send("Access denied");
    }
    next();
  };
};

// Route to get list of users (accessible to admins only)
app.get(
  "/listofusers",
  authenticateToken,
  authorizeRole("admin"),
  (req, res) => {
    res.json(users);
  }
);

// Route to create a new user
app.post("/createuser", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const user = {
      username: req.body.username,
      password: hashedPassword,
      role: req.body.role || "regular", // Default role is 'regular'
    };
    users.push(user);
    res.status(201).send("User created successfully");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// Route to login and get an access token
app.post("/users/login", async (req, res) => {
  const user = users.find((user) => user.username === req.body.username);
  if (user == null) {
    return res.status(400).send("Cannot find user");
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      // Include role in token payload
      const accessToken = jwt.sign(
        { username: user.username, role: user.role },
        process.env.ACCESS_TOKEN_SECRET
      );
      res.json({ accessToken });
    } else {
      res.status(401).send("Passwords did not match");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// Route to get protected data (accessible to admins only)
app.get("/data", authenticateToken, authorizeRole("admin"), (req, res) => {
  console.log("DATA");
  res.send("Protected data");
});

// Route to upload files
app.post(
  "/upload",
  authenticateToken,
  authorizeRole("admin"),
  upload.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).send("No file uploaded");
    }
    res.send(`File uploaded: uploads/${req.file.filename}`);
  }
);

// Start the server
app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on PORT: ${process.env.PORT || 3000}`);
});
