
// server.js (Node.js with Express)
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const http = require("http");
const socketIo = require("socket.io");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const moment = require("moment");
const cloudinary = require('cloudinary').v2;

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*" } });

app.use(cors({
    origin: ['http://localhost:3000', 'https://backend-rt98.onrender.com'],
    methods: ['GET', 'POST'],    
    credentials: true, 
}));
app.use(bodyParser.json());
app.use(express.static("uploads"));
// at the top of server.js
app.use(
  "/uploads",
  express.static(path.join(__dirname, "uploads"))
);

// Set up storage for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      const uploadDir = path.join(__dirname, 'uploads');
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}-${file.originalname}`;
      cb(null, uniqueName);
    }
  });

// Initialize multer
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed!'), false);
      }
    }
  });

cloudinary.config({ 
    cloud_name: 'dgkzqmtgy', 
    api_key: '138712578489821', 
    api_secret: 't60XhGuihc92t01GZtNFpR7dXU0' // Click 'View API Keys' above to copy your API secret
});

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: 17290,
    user: "avnadmin",
    password: process.env.DB_PASSWORD,  // Accessing password from the environment variable
    database: "cleanup_tracker",
    ssl: {
      ca: fs.readFileSync(path.join(__dirname, 'cert', 'ca.pem')),
      rejectUnauthorized: true
    }
  });

db.connect((err) => {
  if (err) {
    console.error("❌ MySQL connection failed:", err);
  } else {
    console.log("✅ Connected to MySQL Database");
  }
});


app.post("/api/login", async (req, res) => {
  const { emailOrUsername, password } = req.body;

  if (!emailOrUsername || !password) {
    return res.status(400).json({ error: "Email/Username and password are required" });
  }

  try {
    const userSql = "SELECT * FROM users WHERE email = ? OR username = ?";
    const [user] = await db.promise().query(userSql, [emailOrUsername, emailOrUsername]);

    if (!user || user.length === 0) {
      return res.status(401).json({ error: "User not found" });
    }

    const passwordMatch = await bcrypt.compare(password, user[0].password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const { user_id, role, status } = user[0];
    res.json({ success: true, user: { user_id, role, status } });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/register", async (req, res) => {
  const { fullName, username, email, password, userType, idImagePath } = req.body;
  console.log("Registration Request Body:", req.body); // Log the received data

  if (!fullName || !username || !email || !password) {
    return res.status(400).json({ message: "All fields are required!" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const query = `INSERT INTO users (fullName, username, email, password, userType, idImagePath, createdAt, role, status)
                   VALUES (?, ?, ?, ?, ?, ?, NOW(), 'User', 'Pending')`;

  db.query(query, [fullName, username, email, hashedPassword, userType, idImagePath], (err, result) => {
    if (err) {
      console.error("Database Error during registration:", err); // Log database errors
      return res.status(500).json({ message: "Database error!" });
    }
    console.log("Registration successful:", result); // Log successful registration
    res.status(201).json({ message: "Registration successful!" });
  });
});
app.get("/api/events/:id/image", (req, res) => {
    const { id } = req.params;
    const sql = "SELECT image_url FROM events WHERE event_id = ?";
    
    db.query(sql, [id], (err, results) => {
      if (err) {
        console.error("Error fetching event image:", err);
        return res.status(500).json({ error: "Database error" });
      }
      
      if (results.length === 0 || !results[0].image_url) {
        return res.status(404).json({ error: "Image not found" });
      }
      
      const imagePath = path.join(__dirname, 'uploads', results[0].image_url);
      res.sendFile(imagePath);
    });
  });
app.get("/api/admin/dashboard", async (req, res) => {
  try {
      const [usersResult] = await db.promise().query("SELECT COUNT(*) AS totalUsers FROM users");
      const [eventsResult] = await db.promise().query("SELECT COUNT(*) AS totalEvents FROM events");
      const [approvalsResult] = await db.promise().query("SELECT COUNT(*) AS totalPending FROM users WHERE status = 'Pending'"); // Assuming 'Pending' is the status for pending approvals
      const [reportsResult] = await db.promise().query("SELECT COUNT(*) AS totalReports FROM reports");

      res.json({
          totalUsers: usersResult[0].totalUsers,
          totalEvents: eventsResult[0].totalEvents,
          pendingApprovals: approvalsResult[0].totalPending,
          reports: reportsResult[0].totalReports,
      });
  } catch (error) {
      console.error("Error fetching dashboard data from MySQL:", error);
      res.status(500).json({ error: "Failed to fetch dashboard data" });
  }
});

let connectedUsers = {};

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("registerUser", (userId) => {
    connectedUsers[userId] = socket.id;

    const sql = "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC";
    db.query(sql, [userId], (err, results) => {
      if (!err && results.length > 0) {
        let lastEventNotification = null;
        for (let i = 0; i < results.length; i++) {
          if (results[i].message.startsWith("New event:")) {
            lastEventNotification = results[i];
            break;
          }
        }
        socket.emit("unreadNotifications", { notifications: results, newEvent: lastEventNotification });
      } else {
        socket.emit("unreadNotifications", { notifications: [], newEvent: null });
      }
    });
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
    Object.keys(connectedUsers).forEach((userId) => {
      if (connectedUsers[userId] === socket.id) delete connectedUsers[userId];
    });
  });
});

app.post("/api/markNotificationsRead", (req, res) => {
  const { notificationId } = req.body;
  const sql = "UPDATE notifications SET is_read = 1 WHERE id = ?";
  db.query(sql, [notificationId], (err) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json({ message: "Notification marked as read" });
  });
});

app.get("/getNotifications", (req, res) => {
  const { userId } = req.query;

  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }

  const sql = `
    SELECT notif_id, user_id, event_id, message, IFNULL(created_at, NOW()) AS created_at
    FROM notifications
    WHERE user_id = ?
    ORDER BY created_at DESC`;

  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching notifications:", err);
      return res.status(500).json({ error: "Database error" });
    }

    let lastEventNotification = null;
    for (let i = 0; i < results.length; i++) {
      if (results[i].message.startsWith("New event:")) {
        lastEventNotification = results[i];
        break;
      }
    }
    res.json({ notifications: results, newEvent: lastEventNotification });
  });
});

app.post("/addEvent", upload.single('image'), (req, res) => {
    const { eventName, description, date, time, location, additionalDetails, createdBy } = req.body;
    const imageUrl = req.file ? req.file.filename : null;
  
    const checkSql = "SELECT * FROM events WHERE event_name = ? AND event_date = ? AND event_time = ?";
    db.query(checkSql, [eventName, date, time], (err, results) => {
      if (err) {
        console.error("❌ Error checking event:", err);
        return res.status(500).json({ error: "Database error" });
      }
      if (results.length > 0) return res.status(400).json({ message: "Event already exists!" });
  
      const insertSql = `INSERT INTO events 
        (event_name, description, event_date, event_time, location, 
         add_details, created_by) 
        VALUES (?, ?, ?, ?, ?, ?, ?)`;
        
      db.query(insertSql, 
        [eventName, description, date, time, location, 
         additionalDetails, createdBy, imageUrl], 
        (err, result) => {
          if (err) {
            console.error("❌ Error inserting event:", err);
            return res.status(500).json({ error: "Failed to add event" });
          }
  
          const eventId = result.insertId;
  
          // Get the newly created event with image URL
          db.query("SELECT * FROM events WHERE event_id = ?", [eventId], (err, eventResults) => {
            if (err) {
              console.error("❌ Error fetching new event:", err);
              return res.status(500).json({ error: "Failed to fetch new event" });
            }
  
            const newEvent = eventResults[0];
            const eventWithImage = {
              ...newEvent,
              imageUrl: newEvent.image_url ? `/uploads/${newEvent.image_url}` : null
            };
  
            const notificationSql = `INSERT INTO notifications (user_id, event_id, message, is_read, created_at) SELECT user_id, ?, ?, 0, NOW() FROM users`;
            db.query(notificationSql, [eventId, `New event: ${eventName}`], (err) => {
              if (err) {
                console.error("❌ Error inserting notifications:", err);
                return res.status(500).json({ error: "Failed to create notifications" });
              }
  
              io.emit("newEvent", eventWithImage);
              res.json({ 
                message: "Event added successfully!",
                event: eventWithImage
              });
            });
          });
        }
      );
    });
  });

app.get("/events", (req, res) => {
  const sql = "SELECT * FROM events ORDER BY event_date ASC";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(results);
  });
});

app.get("/events/:id", (req, res) => {
    const { id } = req.params;
    const sql = `
      SELECT e.*, COUNT(ep.user_id) as participants
      FROM events e
      LEFT JOIN event_participants ep ON e.event_id = ep.event_id
      WHERE e.event_id = ?
      GROUP BY e.event_id`;
      
    db.query(sql, [id], (err, results) => {
      if (err) {
        console.error("Error fetching event details:", err);
        return res.status(500).json({ error: "Database error" });
      }
      if (results.length > 0) {
        const event = results[0];
        res.json({
          ...event,
          imageUrl: event.image_url ? `/uploads/${event.image_url}` : null,
          formattedDate: moment(event.event_date).format('MMMM Do YYYY'),
          formattedTime: moment(event.event_time, 'HH:mm:ss').format('h:mm A'),
          participants: parseInt(event.participants) || 0
        });
      } else {
        res.status(404).json({ message: "Event not found" });
      }
    });
  });

app.get('/api/admin/users', async (req, res) => {
    const filter = req.query.filter;
    let sql = 'SELECT user_id, username, status FROM users';
  
    if (filter && filter !== 'All') {
      sql += ` WHERE status = '${filter}'`;
    }
  
    console.log('API Request received with filter:', filter);
    console.log('SQL Query:', sql);
  
    try {
      const [users] = await db.promise().query(sql);
      console.log('SQL Query Result (users):', users);
  
      const countQueries = {
        approved: `SELECT COUNT(*) as count FROM users WHERE status = 'approved'`,
        pending: `SELECT COUNT(*) as count FROM users WHERE status = 'pending'`,
        restricted: `SELECT COUNT(*) as count FROM users WHERE status = 'restricted'`,
      };
  
      const countResults = await Promise.all(
        Object.values(countQueries).map((query) => db.promise().query(query))
      );
  
      const approvedCount = countResults[0][0][0].count;
      const pendingCount = countResults[1][0][0].count;
      const restrictedCount = countResults[2][0][0].count;
  
      res.json({
        users,
        approvedCount,
        pendingCount,
        restrictedCount,
        totalUsers: users.length,
      });
  
      console.log('API Response sent:', {
        users,
        approvedCount,
        pendingCount,
        restrictedCount,
        totalUsers: users.length,
      });
    } catch (err) {
      console.error('Error fetching users or counts:', err);
      res.status(500).json({ error: 'Database error' });
    }
  });

app.post('/api/admin/users/:userId/status', async (req, res) => {
  const { userId } = req.params;
  const { status } = req.body;

  if (!userId || !status || !['Approved', 'Restricted'].includes(status)) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  try {
    const sql = 'UPDATE users SET status = ? WHERE user_id = ?';
    await db.promise().query(sql, [status, userId]);
    res.json({ message: 'User status updated successfully' });
  } catch (err) {
    console.error('Error updating user status:', err);
    res.status(500).json({ error: 'Database error' });
  }
});
app.post('/events/:eventId/join', async (req, res) => {
    const { eventId } = req.params;
    const userId = req.session?.userId || req.body?.userId;
  
    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated.' });
    }
  
    try {
      const connection = await db.promise();
  
      // Check if the user is already participating in the event
      const [existingParticipant] = await connection.execute(
        `SELECT * FROM event_participants WHERE event_id = ? AND user_id = ?`,
        [eventId, userId]
      );
  
      if (existingParticipant.length > 0) {
        return res.status(409).json({ message: 'User is already participating in this event.' });
      }
  
      // Insert the new participant record
      await connection.execute(
        `INSERT INTO event_participants (event_id, user_id) VALUES (?, ?)`,
        [eventId, userId]
      );
  
      // Get the current participant count for the event.
      const [participantCountResult] = await connection.execute(
        `SELECT COUNT(*) as participantCount FROM event_participants WHERE event_id = ?`,
        [eventId]
      );
      const participantCount = participantCountResult[0].participantCount;
  
      // Optionally, you might want to update an events table with the participant count
      // await connection.execute(
      //   `UPDATE events SET participant_count = ? WHERE id = ?`,
      //   [participantCount, eventId]
      // );
  
      res.status(201).json({
        message: 'Successfully joined the event!',
        participantCount: participantCount, // Return the participant count
      });
    } catch (error) {
      console.error('Error joining event:', error);
      res.status(500).json({ message: 'Failed to join the event.' });
    }
  });
  
  app.get('/events/:eventId/participants', async (req, res) => {
    const { eventId } = req.params;
    try {
      const connection = await db.promise();
      const [participants] = await connection.execute(
        `SELECT u.user_id, u.name, u.email, ep.joined_at
         FROM event_participants ep
         JOIN users u ON ep.user_id = u.user_id
         WHERE ep.event_id = ?`,
        [eventId]
      );
      res.status(200).json({ participants });
    } catch (error) {
      console.error('Error fetching participants for event:', error);
      res.status(500).json({ message: 'Failed to fetch participants for this event.' });
    }
  });

// Endpoint to update user status (e.g., Approve or reject)
app.put('/api/admin/users/:userId', async (req, res) => {
  const { userId } = req.params;
  const { status } = req.body;

  console.log(`Updating user ${userId} to status: ${status}`);

  // Validate the status
  if (!status || (status !== 'Approved' && status !== 'Restricted')) {
    return res.status(400).json({ error: 'Invalid status provided.' });
  }

  try {
    // Use a parameterized query to prevent SQL injection
    const sql = 'UPDATE users SET status = ? WHERE user_id = ?';
    const params = [status, userId];

    const [result] = await db.promise().query(sql, params);

    // Check if the user was found and updated
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found or status not updated.' });
    }

    res.json({ message: 'User status updated successfully.' });

  } catch (err) {
    // Handle database errors
    console.error('Error updating user status:', err);
    res.status(500).json({ error: 'Database error: ' + err.message });
  }
});


app.get('/api/admin/recent-events', async (req, res) => {
    try {
      const [recentEvents] = await db.promise().query(
        'SELECT event_name, event_date, created_at FROM events ORDER BY created_at DESC LIMIT 5' // Added 'created_at' to the SELECT statement
      );
      res.json(recentEvents);
    } catch (error) {
      console.error('Error fetching recent events from MySQL:', error);
      res.status(500).json({ error: 'Failed to fetch recent events' });
    }
});
app.get('/api/admin/participants-per-event', async (req, res) => {
    try {
      const connection = await db.promise();
      const [participants] = await connection.execute(`
        SELECT
          e.event_name,
          COUNT(DISTINCT ep.user_id) AS participant_count
        FROM events e
        LEFT JOIN event_participants ep ON e.event_id = ep.event_id
        GROUP BY e.event_name
        ORDER BY participant_count DESC;
      `);
      res.json(participants);
    } catch (error) {
      console.error('Error fetching participant count per event from MySQL:', error);
      res.status(500).json({ error: 'Failed to fetch participant count per event' });
    }
  });

app.get('/api/admin/report-details', async (req, res) => {
  try {
    const [rows] = await db.promise().query(`
      SELECT
        r.report_id,
        r.user,
        u.fullName   AS full_name,
        r.latitude,
        r.longitude,
        r.description,
        r.timestamp,
        ri.image_path
      FROM reports r
      LEFT JOIN users         u  ON u.user_id        = r.user
      LEFT JOIN report_images ri ON ri.report_id     = r.report_id
    `);

    // fold rows into one object per report_id
    const reports = rows.reduce((acc, r) => {
      if (!acc[r.report_id]) {
        acc[r.report_id] = {
          report_id:  r.report_id,
          user:       r.user,
          full_name:  r.full_name  || 'Unknown User',
          latitude:   r.latitude,
          longitude:  r.longitude,
          description:r.description,
          timestamp:  r.timestamp,
          images:     []
        };
      }
      if (r.image_path) {
        acc[r.report_id].images.push(r.image_path);
      }
      return acc;
    }, {});

    res.json(Object.values(reports));
  } catch (err) {
    console.error("Error fetching reports:", err);
    res.status(500).json({ error: "Failed to fetch reports" });
  }
});

// Report endpoints
app.post("/api/reports", upload.array("images"), async (req, res) => {
  try {
    const { userId, latitude, longitude, description } = req.body;
    const images = req.files;

    if (!userId || !latitude || !longitude || !description) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    if (!images || images.length === 0) {
      return res.status(400).json({ message: "No images uploaded" });
    }

    // Insert report into database
    db.query(
      `INSERT INTO reports (user, latitude, longitude, description, timestamp)
       VALUES (?, ?, ?, ?, NOW())`,
      [userId, latitude, longitude, description],
      async (error, result) => {
        if (error) {
          console.error("Database insert error:", error);
          return res.status(500).json({ message: "Failed to create report" });
        }

        const reportId = result.insertId;

        try {
          // Upload images to Cloudinary and store URLs in database
          const uploadedImages = await Promise.all(
            images.map(async (image) => {
              try {
                // Upload to Cloudinary
                const cloudinaryResult = await cloudinary.uploader.upload(image.path, {
                  folder: "reports",
                  use_filename: true
                });
                
                // Store Cloudinary URL in database
                db.query(
                  `INSERT INTO report_images (report_id, image_url) VALUES (?, ?)`,
                  [reportId, cloudinaryResult.secure_url],
                  (error) => {
                    if (error) {
                      console.error("Failed to insert image URL:", error);
                    }
                  }
                );

                // Delete temporary file after upload
                fs.unlinkSync(image.path);

                return cloudinaryResult.secure_url;
              } catch (uploadError) {
                console.error("Failed to upload image:", uploadError);
                return null;
              }
            })
          );

          res.status(201).json({ 
            message: "Report created and images uploaded successfully!",
            imageUrls: uploadedImages.filter(url => url !== null)
          });

        } catch (error) {
          console.error("Error uploading images:", error);
          res.status(500).json({ 
            message: "Report created but failed to upload some images", 
            error: error.message 
          });
        }
      }
    );

  } catch (error) {
    console.error("Error creating report:", error);
    res.status(500).json({ 
      message: "Failed to create report", 
      error: error.message 
    });
  }
});

// GET user full name by ID
app.get('/api/users/:id', (req, res) => {
  const { id } = req.params;

  const sql = "SELECT fullName FROM users WHERE user_id = ?";
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error('Error fetching user fullName:', err);
      return res.status(500).json({ error: 'Failed to fetch user fullName' });
    }

    if (results.length > 0) {
      res.json(results[0]); // send { fullName: "Juan Dela Cruz" }
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  });
});
// In your server.js
app.get('/api/events/recent', async (req, res) => {
    try {
      const [events] = await db.query(`
        SELECT 
          event_id as id,
          event_name as title,
          description,
          event_date as date,
          location,
          image_url,
          created_at
        FROM events
        ORDER BY created_at DESC
        LIMIT 5
      `);
      
      res.json(events.map(event => ({
        ...event,
        imageUrl: event.image_url ? `/uploads/${event.image_url}` : null,
        formattedDate: moment(event.date).format('MMM DD, YYYY')
      })));
      
    } catch (error) {
      console.error("Error fetching recent events:", error);
      res.status(500).json({ error: "Failed to fetch events" });
    }
  });

  app.get('/api/user/stats/:userId', async (req, res) => {
    const { userId } = req.params;
  
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required.' });
    }
  
    try {
      // Use db.promise().query for database interaction
      const [reportCountResult] = await db.promise().query(
        'SELECT COUNT(*) AS reportCount FROM reports WHERE user = ?',
        [userId]
      );
  
      const [eventCountResult] = await db.promise().query(
        'SELECT COUNT(*) AS eventCount FROM event_participants WHERE user_id = ?',
        [userId]
      );
  
      res.json({
        reportCount: reportCountResult[0].reportCount,
        eventCount: eventCountResult[0].eventCount
      });
    } catch (error) {
      console.error('Error fetching user stats:', error);
      res.status(500).json({ error: 'Database error fetching user statistics' });
    }
});

// Simple test endpoint
app.get('/api/test', (req, res) => {
  res.json({ message: "Backend is working!", timestamp: new Date() });
});



const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});