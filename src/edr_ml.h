/*=============================================================================
 * edr_ml.h - EDR Machine Learning & Threat Intelligence (Phase 4)
 *=============================================================================
 * Advanced threat detection using statistical models, threat intelligence,
 * and automated response capabilities.
 *
 * PHASE 4 MODULES:
 * 1. Anomaly Detection Engine - Statistical profiling and outlier detection
 * 2. Threat Intelligence Integration - IoC matching and reputation scoring
 * 3. Behavioral Clustering - Group similar behaviors for pattern recognition
 * 4. Automated Response - Quarantine, remediation, and threat hunting
 * 5. Forensic Evidence Collection - Memory dumps, process snapshots
 * 6. Threat Correlation - Cross-process attack chain detection
 * 7. Model Training - Online learning from observed behaviors
 *
 * ATTACK PATTERNS DETECTED:
 * - Zero-day exploits (anomaly-based detection)
 * - APT (Advanced Persistent Threat) campaigns
 * - Fileless malware (memory-only attacks)
 * - Living-off-the-land attacks (LOLBins)
 * - Multi-stage attacks (kill chain correlation)
 * - Polymorphic malware (behavioral clustering)
 *
 * INTEGRATION WITH PREVIOUS PHASES:
 * - Phase 1: Syscall filtering → Training data for ML models
 * - Phase 2: Behavioral detection → Feature vectors for clustering
 * - Phase 3: Advanced detection → Alerts feed into correlation engine
 *
 * USAGE:
 *   edr_ml_init();                    // Initialize ML engine
 *   edr_ml_train();                   // Train models on benign behavior
 *   edr_ml_periodic_check();          // Called from timer interrupt
 *   edr_ml_analyze_process(task);     // Analyze process behavior
 *=============================================================================*/
#ifndef EDR_ML_H
#define EDR_ML_H

#include <stdint.h>
#include <stdbool.h>
#include "process.h"

/*=============================================================================
 * CONFIGURATION
 *=============================================================================*/

/* Anomaly detection */
#define EDR_ML_FEATURE_COUNT 32           /* Number of behavioral features */
#define EDR_ML_ANOMALY_THRESHOLD 0.85     /* Threshold for anomaly score (0-1) */
#define EDR_ML_TRAINING_SAMPLES 1000      /* Samples needed for baseline */
#define EDR_ML_SLIDING_WINDOW 100         /* Observation window (ticks) */

/* Threat intelligence */
#define EDR_ML_IOC_MAX_HASHES 256         /* Max malicious file hashes */
#define EDR_ML_IOC_MAX_IPS 128            /* Max malicious IP addresses */
#define EDR_ML_IOC_MAX_DOMAINS 64         /* Max malicious domains */
#define EDR_ML_REPUTATION_THRESHOLD 70    /* Reputation score (0-100) */

/* Behavioral clustering */
#define EDR_ML_MAX_CLUSTERS 16            /* Max behavior clusters */
#define EDR_ML_CLUSTER_SAMPLES 50         /* Samples per cluster */
#define EDR_ML_CLUSTER_FEATURES 16        /* Features for clustering */

/* Automated response */
#define EDR_ML_QUARANTINE_DIR "/quarantine"  /* Quarantine directory */
#define EDR_ML_MAX_REMEDIATION_ACTIONS 32    /* Max remediation steps */

/* Forensic evidence */
#define EDR_ML_MAX_SNAPSHOTS 16           /* Max process snapshots */
#define EDR_ML_SNAPSHOT_SIZE 4096         /* Snapshot buffer size */

/* Threat correlation */
#define EDR_ML_MAX_ATTACK_CHAINS 8        /* Track up to 8 attack chains */
#define EDR_ML_CHAIN_MAX_STEPS 16         /* Max steps in attack chain */
#define EDR_ML_CORRELATION_WINDOW 300000  /* 5 minutes (in ms) */

/*=============================================================================
 * MODULE 1: ANOMALY DETECTION ENGINE
 *=============================================================================
 * Uses statistical models to detect deviations from normal behavior.
 * Implements lightweight ML algorithms suitable for kernel space.
 *=============================================================================*/

/**
 * @brief Feature vector for behavior profiling
 *
 * Each process has a feature vector representing its behavior:
 * - Syscall frequency distribution (read, write, exec, etc.)
 * - Resource usage patterns (CPU, memory, network)
 * - Temporal patterns (activity timing, periodicity)
 * - Process relationships (parent-child, IPC)
 */
typedef struct {
    /* Syscall behavior (normalized 0-1) */
    float syscall_read_rate;          /* Read syscalls per second */
    float syscall_write_rate;         /* Write syscalls per second */
    float syscall_exec_rate;          /* Exec syscalls per second */
    float syscall_network_rate;       /* Network syscalls per second */
    float syscall_memory_rate;        /* Memory syscalls per second */

    /* Resource usage (normalized 0-1) */
    float cpu_usage;                  /* CPU utilization */
    float memory_usage;               /* Memory utilization */
    float network_tx_rate;            /* Network transmit rate */
    float network_rx_rate;            /* Network receive rate */
    float disk_io_rate;               /* Disk I/O rate */

    /* Temporal patterns (normalized 0-1) */
    float activity_variance;          /* Variance in activity level */
    float periodicity_score;          /* Periodic behavior score */
    float burst_intensity;            /* Sudden activity bursts */

    /* Process relationships (normalized 0-1) */
    float child_spawn_rate;           /* Child process creation rate */
    float ipc_activity;               /* Inter-process communication */
    float privilege_escalation;       /* Privilege changes */

    /* Security-specific features (normalized 0-1) */
    float crypto_ops_rate;            /* Cryptographic operations */
    float file_modification_rate;     /* File modification rate */
    float network_connection_rate;    /* New connection rate */
    float suspicious_memory_score;    /* RWX memory, code injection */

    /* Advanced features (normalized 0-1) */
    float edr_alert_rate;             /* EDR alerts per minute */
    float firewall_violation_rate;    /* Firewall violations */
    float ids_trigger_rate;           /* IDS triggers */
    float entropy_score;              /* Data entropy (randomness) */

    /* Padding to reach 32 features */
    float reserved[8];                /* Future features */
} edr_feature_vector_t;

/**
 * @brief Statistical model for baseline behavior
 *
 * Uses Gaussian distribution for each feature:
 * - Mean (μ): Average value
 * - Variance (σ²): Spread of values
 * - Min/Max: Observed range
 */
typedef struct {
    float mean[EDR_ML_FEATURE_COUNT];      /* Feature means */
    float variance[EDR_ML_FEATURE_COUNT];  /* Feature variances */
    float min[EDR_ML_FEATURE_COUNT];       /* Feature minimums */
    float max[EDR_ML_FEATURE_COUNT];       /* Feature maximums */
    uint32_t sample_count;                 /* Number of training samples */
    bool is_trained;                       /* Model is ready */
} edr_baseline_model_t;

/**
 * @brief Anomaly detection result
 */
typedef struct {
    float anomaly_score;              /* Overall anomaly score (0-1) */
    float feature_scores[EDR_ML_FEATURE_COUNT];  /* Per-feature scores */
    uint8_t anomalous_features;       /* Number of anomalous features */
    bool is_anomaly;                  /* Overall anomaly flag */
    uint32_t detection_timestamp;     /* When detected */
} edr_anomaly_result_t;

/**
 * @brief Extract feature vector from process
 * @param task Process to analyze
 * @param features Output feature vector
 */
void edr_ml_extract_features(task_t* task, edr_feature_vector_t* features);

/**
 * @brief Train baseline model on benign behavior
 * @param task Process to learn from
 * @param model Baseline model to update
 */
void edr_ml_train_baseline(task_t* task, edr_baseline_model_t* model);

/**
 * @brief Detect anomalies using trained model
 * @param features Feature vector to analyze
 * @param model Trained baseline model
 * @param result Output anomaly detection result
 * @return true if anomaly detected
 */
bool edr_ml_detect_anomaly(const edr_feature_vector_t* features,
                            const edr_baseline_model_t* model,
                            edr_anomaly_result_t* result);

/**
 * @brief Calculate Mahalanobis distance (multivariate outlier detection)
 * @param features Feature vector
 * @param model Baseline model
 * @return Distance score (higher = more anomalous)
 */
float edr_ml_mahalanobis_distance(const edr_feature_vector_t* features,
                                   const edr_baseline_model_t* model);

/*=============================================================================
 * MODULE 2: THREAT INTELLIGENCE INTEGRATION
 *=============================================================================
 * Matches observed behaviors against known threat indicators.
 *=============================================================================*/

/**
 * @brief Indicator of Compromise (IoC) types
 */
typedef enum {
    IOC_TYPE_FILE_HASH = 0,           /* Malicious file hash (SHA-256) */
    IOC_TYPE_IP_ADDRESS = 1,          /* C2 server IP */
    IOC_TYPE_DOMAIN = 2,              /* Malicious domain */
    IOC_TYPE_PROCESS_NAME = 3,        /* Known malware process name */
    IOC_TYPE_MUTEX = 4,               /* Malware mutex name */
    IOC_TYPE_REGISTRY_KEY = 5,        /* Malicious registry key */
    IOC_TYPE_USER_AGENT = 6,          /* Malicious HTTP user-agent */
    IOC_TYPE_BEHAVIOR_PATTERN = 7     /* Known behavior sequence */
} ioc_type_t;

/**
 * @brief Indicator of Compromise entry
 */
typedef struct {
    ioc_type_t type;                  /* IoC type */
    union {
        uint8_t file_hash[32];        /* SHA-256 hash */
        uint32_t ip_address;          /* IPv4 address */
        char domain[64];              /* Domain name */
        char process_name[32];        /* Process name */
        char mutex_name[64];          /* Mutex name */
    } value;
    uint8_t severity;                 /* 1-10 (10 = critical) */
    uint32_t first_seen;              /* Timestamp first observed */
    uint32_t last_seen;               /* Timestamp last observed */
    bool active;                      /* IoC is active */
} ioc_entry_t;

/**
 * @brief Threat intelligence database
 */
typedef struct {
    ioc_entry_t file_hashes[EDR_ML_IOC_MAX_HASHES];
    ioc_entry_t ip_addresses[EDR_ML_IOC_MAX_IPS];
    ioc_entry_t domains[EDR_ML_IOC_MAX_DOMAINS];
    uint16_t hash_count;
    uint16_t ip_count;
    uint16_t domain_count;
    uint32_t last_update;             /* Timestamp of last TI update */
} threat_intel_db_t;

/**
 * @brief Reputation score
 */
typedef struct {
    uint8_t file_reputation;          /* 0-100 (100 = trusted) */
    uint8_t network_reputation;       /* 0-100 */
    uint8_t process_reputation;       /* 0-100 */
    uint8_t overall_reputation;       /* 0-100 */
    bool is_known_malicious;          /* Matches IoC */
    uint32_t matched_ioc_count;       /* Number of IoC matches */
} reputation_score_t;

/**
 * @brief Add IoC to threat intelligence database
 * @param type IoC type
 * @param value IoC value (hash, IP, domain, etc.)
 * @param severity Severity (1-10)
 * @return true if successfully added
 */
bool edr_ti_add_ioc(ioc_type_t type, const void* value, uint8_t severity);

/**
 * @brief Check if file hash matches known malware
 * @param hash SHA-256 hash
 * @return true if malicious
 */
bool edr_ti_check_file_hash(const uint8_t hash[32]);

/**
 * @brief Check if IP address is malicious
 * @param ip IPv4 address
 * @return true if malicious
 */
bool edr_ti_check_ip(uint32_t ip);

/**
 * @brief Calculate reputation score for process
 * @param task Process to evaluate
 * @param score Output reputation score
 */
void edr_ti_calculate_reputation(task_t* task, reputation_score_t* score);

/**
 * @brief Update threat intelligence database from external source
 * @param source TI feed source (e.g., YARA rules, STIX/TAXII)
 * @return Number of IoCs updated
 */
uint32_t edr_ti_update_database(const char* source);

/*=============================================================================
 * MODULE 3: BEHAVIORAL CLUSTERING
 *=============================================================================
 * Groups similar processes to identify malware families and variants.
 *=============================================================================*/

/**
 * @brief Behavior cluster (represents a malware family or benign group)
 */
typedef struct {
    edr_feature_vector_t centroid;    /* Cluster center (mean features) */
    uint16_t member_count;            /* Number of processes in cluster */
    uint16_t pid_list[EDR_ML_CLUSTER_SAMPLES];  /* Member PIDs */
    bool is_malicious;                /* Cluster classified as malicious */
    uint8_t maliciousness_score;      /* 0-100 */
    char label[32];                   /* Cluster label (e.g., "Ransomware Family X") */
} behavior_cluster_t;

/**
 * @brief Clustering state
 */
typedef struct {
    behavior_cluster_t clusters[EDR_ML_MAX_CLUSTERS];
    uint8_t cluster_count;
    uint32_t total_samples;
    bool is_initialized;
} clustering_state_t;

/**
 * @brief Assign process to nearest cluster (K-means)
 * @param features Process feature vector
 * @param state Clustering state
 * @return Cluster index (0 to cluster_count-1)
 */
uint8_t edr_cluster_assign(const edr_feature_vector_t* features,
                            clustering_state_t* state);

/**
 * @brief Update cluster centroids (K-means iteration)
 * @param state Clustering state
 */
void edr_cluster_update_centroids(clustering_state_t* state);

/**
 * @brief Calculate similarity between two feature vectors (cosine similarity)
 * @param a First feature vector
 * @param b Second feature vector
 * @return Similarity score (0-1, 1 = identical)
 */
float edr_cluster_similarity(const edr_feature_vector_t* a,
                              const edr_feature_vector_t* b);

/**
 * @brief Detect malware family based on clustering
 * @param task Process to analyze
 * @return Cluster index if matches malicious cluster, -1 otherwise
 */
int edr_cluster_detect_family(task_t* task);

/*=============================================================================
 * MODULE 4: AUTOMATED RESPONSE
 *=============================================================================
 * Automated threat remediation and quarantine.
 *=============================================================================*/

/**
 * @brief Response action types
 */
typedef enum {
    RESPONSE_TERMINATE_PROCESS = 0,   /* Kill malicious process */
    RESPONSE_SUSPEND_PROCESS = 1,     /* Suspend (freeze) process */
    RESPONSE_QUARANTINE_FILE = 2,     /* Move file to quarantine */
    RESPONSE_BLOCK_NETWORK = 3,       /* Block network connections */
    RESPONSE_ISOLATE_PROCESS = 4,     /* Restrict process permissions */
    RESPONSE_ROLLBACK_CHANGES = 5,    /* Undo file modifications */
    RESPONSE_COLLECT_EVIDENCE = 6,    /* Take memory snapshot */
    RESPONSE_ALERT_ADMIN = 7          /* Notify administrator */
} response_action_t;

/**
 * @brief Response policy
 */
typedef struct {
    bool auto_terminate;              /* Automatically kill threats */
    bool auto_quarantine;             /* Automatically quarantine files */
    bool auto_block_network;          /* Automatically block C2 */
    bool collect_forensics;           /* Collect evidence */
    uint8_t response_threshold;       /* Min threat score for response (0-100) */
} response_policy_t;

/**
 * @brief Remediation action record
 */
typedef struct {
    response_action_t action;         /* Action taken */
    uint16_t target_pid;              /* Target process PID */
    uint32_t timestamp;               /* When action was taken */
    bool success;                     /* Action succeeded */
    char description[128];            /* Action description */
} remediation_record_t;

/**
 * @brief Execute automated response
 * @param task Target process
 * @param action Response action to take
 * @param reason Reason for response
 * @return true if successful
 */
bool edr_response_execute(task_t* task, response_action_t action, const char* reason);

/**
 * @brief Quarantine malicious file
 * @param filepath File to quarantine
 * @return true if successful
 */
bool edr_response_quarantine_file(const char* filepath);

/**
 * @brief Suspend process (freeze execution)
 * @param task Process to suspend
 * @return true if successful
 */
bool edr_response_suspend_process(task_t* task);

/**
 * @brief Block all network connections for process
 * @param task Process to isolate
 * @return true if successful
 */
bool edr_response_block_network(task_t* task);

/**
 * @brief Rollback file modifications (restore from backup)
 * @param task Process that made modifications
 * @return Number of files restored
 */
uint32_t edr_response_rollback_changes(task_t* task);

/*=============================================================================
 * MODULE 5: FORENSIC EVIDENCE COLLECTION
 *=============================================================================
 * Capture process state and memory for incident investigation.
 *=============================================================================*/

/**
 * @brief Process snapshot for forensics
 */
typedef struct {
    uint16_t pid;                     /* Process ID */
    uint32_t timestamp;               /* Snapshot time */
    uint32_t memory_size;             /* Memory size */
    uint8_t memory_dump[EDR_ML_SNAPSHOT_SIZE];  /* Memory snapshot */
    edr_feature_vector_t features;    /* Behavior snapshot */
    char cmdline[128];                /* Command line */
    char parent_name[32];             /* Parent process name */
    bool is_suspicious;               /* Marked as suspicious */
} process_snapshot_t;

/**
 * @brief Forensic evidence database
 */
typedef struct {
    process_snapshot_t snapshots[EDR_ML_MAX_SNAPSHOTS];
    uint8_t snapshot_count;
    uint32_t total_collected;
    uint32_t last_collection_time;
} forensic_db_t;

/**
 * @brief Collect process snapshot
 * @param task Process to snapshot
 * @return true if successful
 */
bool edr_forensics_snapshot_process(task_t* task);

/**
 * @brief Dump process memory to buffer
 * @param task Process to dump
 * @param buffer Output buffer
 * @param size Buffer size
 * @return Bytes dumped
 */
size_t edr_forensics_dump_memory(task_t* task, uint8_t* buffer, size_t size);

/**
 * @brief Export forensic evidence to file
 * @param filepath Output file path
 * @return true if successful
 */
bool edr_forensics_export_evidence(const char* filepath);

/*=============================================================================
 * MODULE 6: THREAT CORRELATION ENGINE
 *=============================================================================
 * Correlate events across processes to detect multi-stage attacks.
 *=============================================================================*/

/**
 * @brief Attack chain step (MITRE ATT&CK technique)
 */
typedef enum {
    ATTACK_INITIAL_ACCESS = 0,        /* Initial compromise */
    ATTACK_EXECUTION = 1,             /* Code execution */
    ATTACK_PERSISTENCE = 2,           /* Maintain foothold */
    ATTACK_PRIVILEGE_ESCALATION = 3,  /* Gain higher privileges */
    ATTACK_DEFENSE_EVASION = 4,       /* Evade detection */
    ATTACK_CREDENTIAL_ACCESS = 5,     /* Steal credentials */
    ATTACK_DISCOVERY = 6,             /* Enumerate environment */
    ATTACK_LATERAL_MOVEMENT = 7,      /* Move to other systems */
    ATTACK_COLLECTION = 8,            /* Gather data */
    ATTACK_EXFILTRATION = 9,          /* Steal data */
    ATTACK_IMPACT = 10                /* Destroy/encrypt data */
} attack_chain_step_t;

/**
 * @brief Attack chain event
 */
typedef struct {
    attack_chain_step_t step;         /* Attack technique */
    uint16_t pid;                     /* Process involved */
    uint32_t timestamp;               /* When occurred */
    char description[64];             /* Event description */
} attack_event_t;

/**
 * @brief Detected attack chain
 */
typedef struct {
    attack_event_t events[EDR_ML_CHAIN_MAX_STEPS];
    uint8_t event_count;
    uint32_t start_time;              /* Chain start timestamp */
    uint32_t end_time;                /* Chain end timestamp */
    bool is_active;                   /* Chain still evolving */
    uint8_t severity;                 /* 1-10 */
    char attack_name[64];             /* Attack campaign name */
} attack_chain_t;

/**
 * @brief Threat correlation state
 */
typedef struct {
    attack_chain_t chains[EDR_ML_MAX_ATTACK_CHAINS];
    uint8_t chain_count;
    uint32_t total_events;
} correlation_state_t;

/**
 * @brief Add event to correlation engine
 * @param step Attack technique
 * @param pid Process ID
 * @param description Event description
 */
void edr_correlate_add_event(attack_chain_step_t step, uint16_t pid,
                              const char* description);

/**
 * @brief Detect multi-stage attack chains
 * @return Number of active attack chains detected
 */
uint8_t edr_correlate_detect_chains(void);

/**
 * @brief Check if process is part of attack chain
 * @param task Process to check
 * @return Attack chain index if found, -1 otherwise
 */
int edr_correlate_is_part_of_chain(task_t* task);

/*=============================================================================
 * MODULE 7: ONLINE LEARNING
 *=============================================================================
 * Continuously update models based on new observations.
 *=============================================================================*/

/**
 * @brief Model update strategy
 */
typedef enum {
    UPDATE_INCREMENTAL = 0,           /* Update with each sample */
    UPDATE_BATCH = 1,                 /* Update in batches */
    UPDATE_PERIODIC = 2               /* Update on timer */
} model_update_strategy_t;

/**
 * @brief Learning configuration
 */
typedef struct {
    model_update_strategy_t strategy; /* Update strategy */
    float learning_rate;              /* 0-1 (decay factor) */
    uint32_t update_interval;         /* Update frequency (ticks) */
    bool enable_feedback;             /* Learn from false positives */
} learning_config_t;

/**
 * @brief Update models with new observation
 * @param task Process observed
 * @param is_malicious User-provided label (supervised learning)
 */
void edr_ml_update_models(task_t* task, bool is_malicious);

/**
 * @brief Adapt baseline to concept drift
 * @param model Baseline model to adapt
 * @param features New observation
 * @param learning_rate Adaptation rate (0-1)
 */
void edr_ml_adapt_baseline(edr_baseline_model_t* model,
                            const edr_feature_vector_t* features,
                            float learning_rate);

/*=============================================================================
 * CORE PHASE 4 STATE (embedded in task_t)
 *=============================================================================*/

/**
 * @brief Per-process ML/TI state
 */
typedef struct edr_ml_state {
    /* Anomaly detection */
    edr_feature_vector_t current_features;    /* Current behavior */
    edr_anomaly_result_t last_anomaly;        /* Last anomaly result */
    uint32_t anomaly_count;                   /* Total anomalies detected */

    /* Threat intelligence */
    reputation_score_t reputation;            /* Reputation score */
    uint32_t ioc_matches;                     /* Number of IoC matches */

    /* Clustering */
    uint8_t cluster_id;                       /* Assigned cluster */
    float cluster_confidence;                 /* Assignment confidence */

    /* Response */
    bool is_quarantined;                      /* Process quarantined */
    bool is_suspended;                        /* Process suspended */
    uint8_t response_actions_taken;           /* Number of responses */

    /* Forensics */
    bool evidence_collected;                  /* Snapshot taken */
    uint32_t snapshot_index;                  /* Index in forensic DB */

    /* Master switch */
    bool ml_enabled;                          /* ML detection enabled */
} edr_ml_state_t;

/*=============================================================================
 * CORE FUNCTIONS
 *=============================================================================*/

/**
 * @brief Initialize ML and threat intelligence system
 */
void edr_ml_init(void);

/**
 * @brief Initialize ML state for a process
 * @param task Process to initialize
 */
void edr_ml_init_process(task_t* task);

/**
 * @brief Train baseline models (call during system initialization)
 * @param training_duration Training time in ticks
 */
void edr_ml_train(uint32_t training_duration);

/**
 * @brief Periodic ML check (called from timer interrupt)
 *
 * Performs:
 * - Feature extraction
 * - Anomaly detection
 * - Threat intelligence lookup
 * - Behavioral clustering
 * - Threat correlation
 * - Automated response (if enabled)
 */
void edr_ml_periodic_check(void);

/**
 * @brief Analyze process with full ML pipeline
 * @param task Process to analyze
 * @return Threat score (0-100, 100 = critical threat)
 */
uint8_t edr_ml_analyze_process(task_t* task);

/**
 * @brief Get global ML statistics
 * @param total_anomalies Output: Total anomalies detected
 * @param total_ioc_matches Output: Total IoC matches
 * @param total_chains Output: Total attack chains
 */
void edr_ml_get_stats(uint32_t* total_anomalies, uint32_t* total_ioc_matches,
                       uint32_t* total_chains);

/**
 * @brief Enable/disable ML detection for process
 * @param task Process to configure
 * @param enabled Enable flag
 */
void edr_ml_set_enabled(task_t* task, bool enabled);

/*=============================================================================
 * PHASE 4a MVP: NEW FUNCTION DECLARATIONS (Not in original design)
 *=============================================================================*/

/* Threat Intelligence - NEW functions */
void edr_ti_init(void);
bool edr_ti_add_file_hash(const uint8_t hash[32], uint8_t severity, const char* name);
bool edr_ti_add_ip(uint32_t ip, uint8_t severity, const char* description);
uint32_t edr_ti_load_csv(const char* filepath);
void edr_ti_get_stats(uint32_t* total_checks, uint32_t* total_matches,
                       uint16_t* hash_count, uint16_t* ip_count);

/* Automated Response - NEW functions */
void edr_response_init(void);
bool edr_response_terminate(task_t* task);
void edr_response_set_policy(const response_policy_t* policy);
void edr_response_get_policy(response_policy_t* policy);
bool edr_response_should_execute(uint8_t threat_score);
void edr_response_get_stats(uint32_t* total_responses, uint8_t* log_count);

/*=============================================================================
 * PHASE 4a: EDR DAEMON - Background Monitoring Process
 *=============================================================================*/

/**
 * @brief Start the EDR background daemon process
 *
 * Creates a high-priority, unkillable background process that continuously
 * monitors the system for threats and coordinates automated responses.
 *
 * The daemon performs:
 * - Periodic full-system threat scans (every 5 seconds)
 * - Process hash validation against Threat Intelligence database
 * - Behavioral anomaly monitoring
 * - Automated threat response coordination
 * - System health status reporting (every 60 seconds)
 *
 * @note The daemon is automatically protected with CAP_UNKILLABLE
 */
void edr_daemon_start(void);

/**
 * @brief Stop the EDR daemon process
 *
 * Signals the daemon to shut down gracefully. The daemon will complete
 * its current scan before terminating.
 */
void edr_daemon_stop(void);

/**
 * @brief Get EDR daemon statistics
 *
 * Retrieves performance and detection statistics from the EDR daemon.
 *
 * @param scans Total number of scans performed
 * @param threats Total number of threats detected
 * @param processes Total number of processes scanned
 * @param responses Total number of automated responses executed
 */
void edr_daemon_get_stats(uint32_t* scans, uint32_t* threats,
                          uint32_t* processes, uint32_t* responses);

#endif /* EDR_ML_H */
