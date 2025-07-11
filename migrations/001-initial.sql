
-- Create Categories table
CREATE TABLE IF NOT EXISTS Categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

-- Create SecurityTools table
CREATE TABLE IF NOT EXISTS SecurityTools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    executionCmd TEXT NOT NULL,
    categoryId INTEGER NOT NULL,
    FOREIGN KEY (categoryId) REFERENCES Categories(id) ON DELETE CASCADE
);
