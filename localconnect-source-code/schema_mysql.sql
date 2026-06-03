CREATE DATABASE IF NOT EXISTS localconnect;
USE localconnect;

CREATE TABLE users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('customer', 'provider', 'admin') NOT NULL,
  phone VARCHAR(20),
  location VARCHAR(120),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE service_providers (
  provider_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  service_type VARCHAR(80) NOT NULL,
  phone VARCHAR(20) NOT NULL,
  address TEXT NOT NULL,
  location VARCHAR(120) NOT NULL,
  rating FLOAT DEFAULT 0,
  availability VARCHAR(40) DEFAULT 'Available',
  verified BOOLEAN DEFAULT FALSE,
  price DECIMAL(10, 2) DEFAULT 0,
  bio TEXT,
  latitude DECIMAL(10, 7),
  longitude DECIMAL(10, 7),
  emergency_enabled BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE bookings (
  booking_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  provider_id INT NOT NULL,
  date DATE NOT NULL,
  time TIME NOT NULL,
  status VARCHAR(30) DEFAULT 'Pending',
  notes TEXT,
  emergency BOOLEAN DEFAULT FALSE,
  amount DECIMAL(10, 2) DEFAULT 0,
  payment_status VARCHAR(30) DEFAULT 'Unpaid',
  payment_provider VARCHAR(40),
  payment_reference VARCHAR(180),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id),
  FOREIGN KEY (provider_id) REFERENCES service_providers(provider_id)
);

CREATE TABLE reviews (
  review_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  provider_id INT NOT NULL,
  booking_id INT,
  rating INT NOT NULL CHECK (rating BETWEEN 1 AND 5),
  comment TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id),
  FOREIGN KEY (provider_id) REFERENCES service_providers(provider_id),
  FOREIGN KEY (booking_id) REFERENCES bookings(booking_id)
);

CREATE TABLE notifications (
  notification_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  message TEXT NOT NULL,
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE messages (
  message_id INT AUTO_INCREMENT PRIMARY KEY,
  booking_id INT NOT NULL,
  sender_id INT NOT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (booking_id) REFERENCES bookings(booking_id),
  FOREIGN KEY (sender_id) REFERENCES users(user_id)
);

CREATE TABLE reports (
  report_id INT AUTO_INCREMENT PRIMARY KEY,
  provider_id INT NOT NULL,
  user_id INT NOT NULL,
  reason TEXT NOT NULL,
  status VARCHAR(30) DEFAULT 'Open',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (provider_id) REFERENCES service_providers(provider_id),
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE password_reset_otps (
  otp_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  otp_hash VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  used_at DATETIME,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE admin_audit_logs (
  audit_id INT AUTO_INCREMENT PRIMARY KEY,
  admin_id INT NOT NULL,
  action VARCHAR(80) NOT NULL,
  target_type VARCHAR(80) NOT NULL,
  target_id INT NOT NULL,
  details TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (admin_id) REFERENCES users(user_id)
);
