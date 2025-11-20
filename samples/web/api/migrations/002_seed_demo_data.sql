-- Comprehensive seed data for ABAC demonstration
-- This file adds additional users and datasets to showcase various access control scenarios

-- Clear existing sample data (keep schema)
DELETE FROM datasets;
DELETE FROM users;

-- ============================================================================
-- USERS - Multiple departments with varying roles
-- ============================================================================

-- Engineering Department
INSERT INTO users (name, email, title) VALUES
    ('Alice Johnson', 'alice@example.com', 'Senior ML Engineer'),
    ('Bob Smith', 'bob@example.com', 'Research Assistant'),
    ('Eve Martinez', 'eve@example.com', 'Engineering Director'),
    ('Frank Chen', 'frank@example.com', 'Data Scientist'),
    ('Grace Kim', 'grace@example.com', 'Junior Researcher');

-- Biology Department
INSERT INTO users (name, email, title) VALUES
    ('Carol Davis', 'carol@example.com', 'Principal Investigator'),
    ('David Wilson', 'david@example.com', 'Lab Technician'),
    ('Helen Park', 'helen@example.com', 'Research Scientist'),
    ('Igor Petrov', 'igor@example.com', 'Department Head');

-- Physics Department
INSERT INTO users (name, email, title) VALUES
    ('Jack Thompson', 'jack@example.com', 'Quantum Researcher'),
    ('Karen Lee', 'karen@example.com', 'Graduate Student'),
    ('Liam O''Brien', 'liam@example.com', 'Professor');

-- Chemistry Department
INSERT INTO users (name, email, title) VALUES
    ('Maria Garcia', 'maria@example.com', 'Organic Chemist'),
    ('Noah Williams', 'noah@example.com', 'Lab Assistant'),
    ('Olivia Brown', 'olivia@example.com', 'Department Chair');

-- Data Science Department (cross-functional)
INSERT INTO users (name, email, title) VALUES
    ('Peter Zhang', 'peter@example.com', 'Chief Data Scientist'),
    ('Quinn Taylor', 'quinn@example.com', 'ML Engineer'),
    ('Rachel Green', 'rachel@example.com', 'Data Analyst');

-- Also add the Keycloak test user
INSERT INTO users (name, email, title) VALUES
    ('Test User', 'user123@stratium.local', 'Developer');

-- Also add the Keycloak test admin
INSERT INTO users (name, email, title) VALUES
    ('Admin User', 'admin456@stratium.local', 'Administrator');

-- ============================================================================
-- DATASETS - Diverse data across departments
-- ============================================================================

-- Engineering Department Datasets
INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Neural Network Training Data v2.1',
    'Large-scale labeled image dataset for training deep learning models. Contains 1M+ images across 1000 categories with bounding box annotations.',
    id,
    'https://storage.example.com/datasets/nn-training-v2.1.tar.gz',
    'engineering',
    ARRAY['machine-learning', 'computer-vision', 'neural-networks', 'deep-learning', 'images']
FROM users WHERE email = 'alice@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'IoT Sensor Telemetry Q1-Q2 2024',
    'Real-time sensor data from 500+ IoT devices across manufacturing facilities. Includes temperature, pressure, humidity, and vibration metrics.',
    id,
    'https://storage.example.com/datasets/iot-telemetry-2024-h1.parquet',
    'engineering',
    ARRAY['iot', 'sensors', 'manufacturing', 'time-series', 'monitoring']
FROM users WHERE email = 'alice@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Autonomous Vehicle Simulation Logs',
    'Driving scenario simulations with LiDAR point clouds, camera feeds, and vehicle control data for autonomous driving research.',
    id,
    'https://storage.example.com/datasets/av-sim-logs-batch3.zip',
    'engineering',
    ARRAY['autonomous-vehicles', 'simulation', 'lidar', 'robotics']
FROM users WHERE email = 'frank@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Network Traffic Analysis Dataset',
    'Anonymized network packet captures for intrusion detection and anomaly detection research. 48 hours of enterprise network traffic.',
    id,
    'https://storage.example.com/datasets/network-traffic-20240315.pcap.gz',
    'engineering',
    ARRAY['networking', 'security', 'intrusion-detection', 'anomaly-detection']
FROM users WHERE email = 'frank@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Robotics Manipulation Demonstrations',
    'Video and trajectory data from robotic arm manipulation tasks. Includes pick-and-place, assembly, and deformable object handling.',
    id,
    'https://storage.example.com/datasets/robot-manipulation-demos.hdf5',
    'engineering',
    ARRAY['robotics', 'manipulation', 'imitation-learning', 'control']
FROM users WHERE email = 'grace@example.com';

-- Biology Department Datasets
INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Plant Genomic Sequences Collection',
    'Whole genome sequences from 50 plant species for comparative genomics and evolutionary studies. Includes annotation files.',
    id,
    'https://storage.example.com/datasets/plant-genomes-v5.0.fasta.gz',
    'biology',
    ARRAY['genomics', 'dna', 'plants', 'evolution', 'sequencing']
FROM users WHERE email = 'carol@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Protein Structure Database',
    'Curated collection of 10,000+ protein structures in PDB format for molecular docking, drug discovery, and structural analysis.',
    id,
    'https://storage.example.com/datasets/protein-structures-curated.tar.gz',
    'biology',
    ARRAY['proteins', 'molecular-biology', 'structures', 'drug-discovery']
FROM users WHERE email = 'carol@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Microscopy Cell Images - Cancer Research',
    'High-resolution microscopy images of cancer cell lines under various treatment conditions. Includes fluorescence and brightfield.',
    id,
    'https://storage.example.com/datasets/cancer-cell-microscopy.zip',
    'biology',
    ARRAY['microscopy', 'cancer', 'cell-biology', 'imaging', 'medical']
FROM users WHERE email = 'helen@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'RNA-Seq Expression Profiles',
    'Transcriptome data from 200 tissue samples across multiple conditions. Processed counts and differential expression analysis results.',
    id,
    'https://storage.example.com/datasets/rnaseq-expression-study1.h5ad',
    'biology',
    ARRAY['rna-seq', 'gene-expression', 'transcriptomics', 'bioinformatics']
FROM users WHERE email = 'helen@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Microbial Diversity 16S Survey',
    '16S rRNA gene sequencing data from soil and water samples. Includes taxonomy classification and abundance tables.',
    id,
    'https://storage.example.com/datasets/16s-microbial-survey.biom',
    'biology',
    ARRAY['microbiology', '16s', 'metagenomics', 'biodiversity']
FROM users WHERE email = 'david@example.com';

-- Physics Department Datasets
INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Quantum Computing Simulation Results',
    'Simulation outputs from quantum circuit experiments on 50-qubit systems. Includes state vectors and measurement outcomes.',
    id,
    'https://storage.example.com/datasets/quantum-sim-results-batch7.hdf5',
    'physics',
    ARRAY['quantum-computing', 'simulation', 'qubits', 'quantum-circuits']
FROM users WHERE email = 'jack@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Particle Collision Event Data',
    'High-energy physics collision events from particle accelerator experiments. Raw detector readouts and reconstructed tracks.',
    id,
    'https://storage.example.com/datasets/particle-collisions-run42.root',
    'physics',
    ARRAY['particle-physics', 'collisions', 'accelerator', 'high-energy']
FROM users WHERE email = 'jack@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Gravitational Wave Detector Noise',
    'Background noise characterization data from LIGO-like gravitational wave detectors for signal processing research.',
    id,
    'https://storage.example.com/datasets/gw-detector-noise-2024.csv',
    'physics',
    ARRAY['gravitational-waves', 'signal-processing', 'astrophysics', 'detectors']
FROM users WHERE email = 'karen@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Superconductor Material Properties',
    'Experimental measurements of electrical and magnetic properties for 150 superconducting materials at various temperatures.',
    id,
    'https://storage.example.com/datasets/superconductor-properties.xlsx',
    'physics',
    ARRAY['superconductors', 'materials-science', 'condensed-matter', 'experimental']
FROM users WHERE email = 'liam@example.com';

-- Chemistry Department Datasets
INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Organic Compound Spectroscopy Database',
    'NMR, IR, and mass spectrometry data for 5000+ organic compounds. Includes chemical structures and peak assignments.',
    id,
    'https://storage.example.com/datasets/organic-spectroscopy-db.sdf',
    'chemistry',
    ARRAY['spectroscopy', 'nmr', 'organic-chemistry', 'characterization']
FROM users WHERE email = 'maria@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Chemical Reaction Outcomes Dataset',
    'Results from 100,000+ chemical reactions including yields, conditions, and product distributions for ML prediction tasks.',
    id,
    'https://storage.example.com/datasets/reaction-outcomes-v3.csv',
    'chemistry',
    ARRAY['reactions', 'synthesis', 'machine-learning', 'chemistry-ml']
FROM users WHERE email = 'maria@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Catalyst Performance Screening',
    'High-throughput screening data for catalytic reactions. Includes conversion rates, selectivity, and stability metrics.',
    id,
    'https://storage.example.com/datasets/catalyst-screening-2024.parquet',
    'chemistry',
    ARRAY['catalysis', 'high-throughput', 'screening', 'materials']
FROM users WHERE email = 'noah@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Environmental Chemistry Water Samples',
    'Chemical analysis of water samples from 50 sites. Includes pollutant concentrations, pH, and trace metal analysis.',
    id,
    'https://storage.example.com/datasets/water-chemistry-survey.csv',
    'chemistry',
    ARRAY['environmental', 'water-quality', 'analytical-chemistry', 'pollution']
FROM users WHERE email = 'olivia@example.com';

-- Data Science Department Datasets (Cross-functional)
INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Multi-Domain Benchmark Dataset',
    'Standardized benchmark tasks spanning NLP, computer vision, and time series. Used for cross-domain model evaluation.',
    id,
    'https://storage.example.com/datasets/multi-domain-benchmark-v2.zip',
    'data-science',
    ARRAY['benchmarks', 'evaluation', 'multi-domain', 'nlp', 'computer-vision']
FROM users WHERE email = 'peter@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Federated Learning Privacy Testbed',
    'Synthetic datasets for testing federated learning algorithms with differential privacy guarantees.',
    id,
    'https://storage.example.com/datasets/federated-learning-testbed.tar.gz',
    'data-science',
    ARRAY['federated-learning', 'privacy', 'differential-privacy', 'distributed']
FROM users WHERE email = 'quinn@example.com';

INSERT INTO datasets (title, description, owner_id, data_url, department, tags)
SELECT
    'Research Metrics Analytics',
    'Aggregated metrics from institutional research projects: publications, citations, funding, and collaborations.',
    id,
    'https://storage.example.com/datasets/research-metrics-2024.json',
    'data-science',
    ARRAY['analytics', 'metrics', 'research', 'bibliometrics']
FROM users WHERE email = 'rachel@example.com';

-- ============================================================================
-- SUMMARY STATISTICS
-- ============================================================================

-- Display summary of seeded data
DO $$
DECLARE
    user_count INTEGER;
    dataset_count INTEGER;
    dept_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO user_count FROM users;
    SELECT COUNT(*) INTO dataset_count FROM datasets;

    RAISE NOTICE '=================================================';
    RAISE NOTICE 'Demo Database Seeded Successfully!';
    RAISE NOTICE '=================================================';
    RAISE NOTICE 'Total Users: %', user_count;
    RAISE NOTICE 'Total Datasets: %', dataset_count;
    RAISE NOTICE '';
    RAISE NOTICE 'Access Control Scenarios:';
    RAISE NOTICE '  - Department-based isolation (engineering, biology, physics, chemistry, data-science)';
    RAISE NOTICE '  - Role-based permissions (admin, editor, viewer)';
    RAISE NOTICE '  - Owner-based access (users can edit their own datasets)';
    RAISE NOTICE '  - Cross-department admin access (admins can access all departments)';
    RAISE NOTICE '=================================================';
END $$;