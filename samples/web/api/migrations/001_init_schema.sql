-- Micro Research Repository Database Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    title VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Datasets table
CREATE TABLE IF NOT EXISTS datasets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data_url VARCHAR(512) NOT NULL,
    department VARCHAR(100) NOT NULL,
    tags TEXT[], -- Array of tags
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_datasets_owner ON datasets(owner_id);
CREATE INDEX IF NOT EXISTS idx_datasets_department ON datasets(department);
CREATE INDEX IF NOT EXISTS idx_datasets_tags ON datasets USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_datasets_created_at ON datasets(created_at DESC);

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers to auto-update updated_at
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_datasets_updated_at
    BEFORE UPDATE ON datasets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Sample seed data
INSERT INTO users (name, email, title) VALUES
    ('Alice Johnson', 'alice@example.com', 'Senior Researcher'),
    ('Bob Smith', 'bob@example.com', 'Research Assistant'),
    ('Carol Davis', 'carol@example.com', 'Principal Investigator'),
    ('David Wilson', 'david@example.com', 'Lab Technician'),
    ('Eve Martinez', 'eve@example.com', 'System Administrator');

-- Sample datasets (using Alice's ID for owner_id)
INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Neural Network Training Data',
    'Dataset containing labeled images for training convolutional neural networks',
    id,
    'https://storage.example.com/datasets/nn-training-v1.zip',
    'engineering',
    ARRAY['machine-learning', 'computer-vision', 'neural-networks']
FROM users WHERE email = 'alice@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Sensor Telemetry 2024',
    'IoT sensor data collected from manufacturing floor during Q1 2024',
    id,
    'https://storage.example.com/datasets/sensor-telemetry-2024q1.csv',
    'engineering',
    ARRAY['iot', 'sensors', 'manufacturing']
FROM users WHERE email = 'alice@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Genomic Sequences Collection',
    'DNA sequences from various plant species for comparative genomics study',
    id,
    'https://storage.example.com/datasets/genomic-sequences-v3.fasta',
    'biology',
    ARRAY['genomics', 'dna', 'plants']
FROM users WHERE email = 'carol@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Protein Structure Database',
    ' 3D protein structures in PDB format for molecular docking simulations',
    id,
    'https://storage.example.com/datasets/protein-structures.tar.gz',
    'biology',
    ARRAY['proteins', 'molecular-biology', 'structures']
FROM users WHERE email = 'carol@example.com';