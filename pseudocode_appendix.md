# Pseudocode Pipeline Migrasi PHP
## Lampiran — Muhammad Farrel Akbar

---

## Modul 1: `main.py` — Orkestrator Pipeline Utama

```
PROGRAM: MigrationPipeline

FUNCTION main():
    args <- parse_command_line_arguments()
        // --input, --output, --reports, --skip-ai, --model,
        // --compare-all, --target-php, --php-version, --prompt-mode, dll.

    IF output_dir is NOT empty THEN
        prompt user "Hapus isi output/? [Y/n]"
        IF user confirms THEN
            delete contents of output_dir
        ELSE
            exit program
        END IF
    END IF

    result <- run_pipeline(args)

    IF result.iso_status == COMPLIANT THEN
        exit with code 0
    ELSE
        exit with code 1
    END IF
END FUNCTION


FUNCTION run_pipeline(input_dir, output_dir, reports_dir, options):
    record start_time

    // --- Step 1: Pre-Conversion Security Scan ---
    pre_scan <- run_scan(input_dir)

    // --- Step 2: PHP Migration ---
    conversion <- run_conversion(input_dir, output_dir, target_version)

    // --- Step 2b: Composer Dependency Analysis ---
    composer_analysis <- run_composer_analysis(input_dir, target_version)

    // --- Step 3: Post-Conversion Security Scan ---
    IF conversion succeeded THEN
        post_scan <- run_scan(output_dir)
    END IF

    // --- Step 4: Static Analysis ---
    IF conversion succeeded THEN
        analysis <- run_analysis(output_dir, phpstan_level, php_version)
    END IF

    // --- Step 5: AI-Assisted Review ---
    IF skip_ai == FALSE THEN
        IF compare_all == TRUE THEN
            run_llm_comparison(pre_scan.findings, all_models, 3_runs_each)
        ELSE
            ai_recs <- run_ai_analysis(pre_scan.findings, selected_model)
        END IF
    END IF

    // --- Step 6: ISO 27001:2022 Compliance Mapping ---
    iso_report <- run_iso_mapping(pre_scan, analysis, ai_recs, output_path)

    total_duration <- now() - start_time

    print_summary_table(pre_scan, post_scan, conversion, analysis, iso_report)
    save_pipeline_result_json(reports_dir, timestamp)

    RETURN PipelineResult(pre_scan, conversion, post_scan, analysis,
                          ai_recs, iso_report, composer_analysis, duration)
END FUNCTION
```

---

## Modul 2: `scanner.py` — Pemindaian Keamanan (Semgrep)

```
PROGRAM: SemgrepScanner

DATA STRUCTURE ScanFinding:
    rule_id, file_path, line_start, line_end
    message, severity        // ERROR | WARNING | INFO
    code_snippet
    vuln_type                // SQL Injection | XSS | Deprecated Function | ...
    iso_controls             // e.g. ["A.8.28", "A.8.26"]
    priority                 // 1..6 (1 = highest)

DATA STRUCTURE ScanResult:
    findings: list of ScanFinding   // sorted by priority
    summary:  ScanSummary           // aggregate counts
    raw_output: JSON dict

CONSTANT VULNERABILITY_RULES:
    priority 1: SQL Injection     -> ISO [A.8.28, A.8.26]
    priority 2: XSS               -> ISO [A.8.28, A.8.26]
    priority 3: Deprecated Function -> ISO [A.8.25, A.8.28]
    priority 4: Hardcoded Credentials -> ISO [A.5.17, A.8.28]
    priority 5: SSRF / Path Traversal -> ISO [A.8.28, A.8.29]
    priority 6: Weak Cryptography -> ISO [A.8.24, A.8.28]


FUNCTION run_scan(target_path):
    IF local rules/ directory exists THEN
        rulesets <- local rules/ directory    // pinned, reproducible
    ELSE
        rulesets <- ["p/php", "p/owasp-top-ten"]   // online registry
    END IF

    cmd <- build_semgrep_command(target_path, rulesets, "--json")
    raw_json <- invoke_subprocess(cmd, timeout=300s)

    findings <- []
    FOR each result in raw_json["results"] DO
        rule_id  <- result.check_id
        severity <- result.extra.severity
        message  <- result.extra.message
        snippet  <- result.extra.lines

        (vuln_type, iso_controls, priority) <- classify(rule_id, message)

        findings.append(ScanFinding(...))
    END FOR

    findings.sort(by priority ASC, then severity, then file_path)

    summary <- aggregate(findings)
    print_summary_table(summary)

    RETURN ScanResult(findings, summary, raw_json)
END FUNCTION


FUNCTION classify(rule_id, message):
    haystack <- lowercase(rule_id + message[:100])

    FOR each (keywords, label, controls, priority) in VULNERABILITY_RULES DO
        IF any keyword in haystack THEN
            RETURN (label, controls, priority)
        END IF
    END FOR

    RETURN ("Other", ["A.8.28"], priority=99)
END FUNCTION
```

---

## Modul 3: `converter.py` — Konversi PHP (Rector)

```
PROGRAM: RectorConverter

DATA STRUCTURE ConversionFile:
    source_path, output_path
    php_version        // PHP5 | PHP7 | UNKNOWN
    status             // CONVERTED | SKIPPED | FAILED
    changes_count
    applied_rectors    // list of Rector rule class names
    iso_controls       // ["A.8.25"]

DATA STRUCTURE ConversionResult:
    files:   list of ConversionFile
    summary: ConversionSummary
    rector_raw_output: string (JSON)

CONSTANT LEVEL_SETS_PHP5:
    UP_TO_PHP_53, UP_TO_PHP_54, ..., UP_TO_PHP_85   // full chain

CONSTANT LEVEL_SETS_PHP7:
    UP_TO_PHP_70, ..., UP_TO_PHP_85   // shorter chain

CONSTANT QUALITY_SETS:
    CODE_QUALITY, DEAD_CODE, EARLY_RETURN, TYPE_DECLARATION


FUNCTION run_conversion(input_path, output_path, target_version):
    php_files <- collect_all_php_files(input_path)

    // Step 1: Detect PHP version per file
    version_map <- {}
    FOR each file in php_files DO
        version_map[file] <- detect_php_version(file)
    END FOR

    // Step 2: Choose Rector level-set chain
    IF PHP5 in version_map.values() THEN
        level_sets <- LEVEL_SETS_PHP5 truncated at target_version
    ELSE
        level_sets <- LEVEL_SETS_PHP7 truncated at target_version
    END IF
    all_sets <- level_sets + QUALITY_SETS

    // Step 3: Copy input/ -> output/ (never modify input/)
    copy_tree(input_path, output_path)

    // Step 4: Snapshot SHA-256 hashes BEFORE Rector
    pre_hashes <- snapshot_sha256(output_path)

    // Step 5: Write temporary rector.php config to system temp dir
    config_path <- write_rector_config(output_path, all_sets)

    // Step 6: Invoke Rector subprocess
    (exit_code, stdout, stderr) <- invoke_rector(config_path, timeout=600s)

    // Step 7: Snapshot SHA-256 hashes AFTER Rector
    post_hashes <- snapshot_sha256(output_path)

    // Step 8: Delete temporary config
    delete(config_path)

    // Step 9: Build per-file results by comparing hashes
    rector_data <- parse_rector_json(stdout)
    FOR each source_file in php_files DO
        pre  <- pre_hashes[output_copy_of(source_file)]
        post <- post_hashes[output_copy_of(source_file)]

        IF file is in rector error list THEN
            status <- FAILED
        ELSE IF pre != post THEN
            status <- CONVERTED
        ELSE
            status <- SKIPPED
        END IF

        files.append(ConversionFile(source_file, status, ...))
    END FOR

    summary <- aggregate(files, elapsed_time)
    print_summary_table(summary)

    RETURN ConversionResult(files, summary, stdout)
END FUNCTION


FUNCTION detect_php_version(file_path):
    content <- read first 8KB of file

    IF any PHP5 pattern matches (mysql_connect, ereg, split, etc.) THEN
        RETURN PHP5
    END IF

    IF any PHP7 pattern matches (fn =>, ??, intdiv, etc.) THEN
        RETURN PHP7
    END IF

    RETURN UNKNOWN
END FUNCTION
```

---

## Modul 4: `analyzer.py` — Analisis Statis (PHPStan)

```
PROGRAM: PHPStanAnalyzer

DATA STRUCTURE AnalysisError:
    file_path, line
    message, severity   // ERROR | WARNING
    iso_controls

DATA STRUCTURE AnalysisResult:
    errors:     list of AnalysisError   // sorted by file, then line
    summary:    AnalysisSummary
    raw_output: JSON dict

CONSTANT CI3_FRAMEWORK_NOISE:
    // False positives from CodeIgniter 3 architecture:
    "extends unknown class CI_*"
    "Constant ENVIRONMENT/FCPATH/APPPATH not found"
    "$this->db, $this->input, $this->session, ..."
    "Function base_url/redirect/form_open not found"
    // These are filtered out before returning results.


FUNCTION run_analysis(target_path, level, php_version):
    // Resolve best available PHPStan binary
    phpstan_exe <- find_phpstan(vendor/bin/ OR global PATH)

    cmd <- build_phpstan_command(target_path, level, php_version,
                                 "--error-format=json", "--no-progress")
    (exit_code, stdout, stderr) <- invoke_subprocess(cmd, timeout=300s)

    raw_json <- parse_phpstan_json(stdout)

    errors <- []
    noise_count <- 0
    FOR each (file_path, file_data) in raw_json["files"] DO
        FOR each msg_entry in file_data["messages"] DO
            message <- msg_entry.message
            line    <- msg_entry.line

            IF message matches CI3_FRAMEWORK_NOISE THEN
                noise_count <- noise_count + 1
                CONTINUE   // skip false positive
            END IF

            (severity, iso_controls) <- classify_error(message)
            errors.append(AnalysisError(file_path, line, message,
                                        severity, iso_controls))
        END FOR
    END FOR

    errors.sort(by file_path, then line)

    summary <- aggregate(errors, noise_count, elapsed_time)
    print_results_table(errors, summary)

    RETURN AnalysisResult(errors, summary, raw_json)
END FUNCTION


FUNCTION classify_error(message):
    lower_msg <- lowercase(message)

    IF "dead code" OR "unreachable" OR "never returns" in lower_msg THEN
        RETURN ("WARNING", ["A.8.25"])
    END IF

    IF "undefined" OR "not found" OR "unknown class" in lower_msg THEN
        RETURN ("ERROR", ["A.8.28", "A.8.25"])
    END IF

    IF "type" OR "null" OR "incompatible" OR "expects" in lower_msg THEN
        RETURN ("ERROR", ["A.8.28"])
    END IF

    RETURN ("ERROR", ["A.8.28"])   // fallback
END FUNCTION
```

---

## Modul 5: `ai_engine.py` — Analisis AI (LLM via Ollama)

```
PROGRAM: PHPAIEngine

DATA STRUCTURE AIRecommendation:
    original_code, suggested_fix, explanation
    confidence     // 0.0 - 1.0
    iso_controls, vuln_type
    file_path, line_start
    model_used, fim_used

CONSTANT COMPARISON_MODELS:
    ["deepseek-coder:6.7b", "qwen2.5-coder:7b", "codellama:7b",
     "mistral:7b", "llama3.1:8b"]

CONSTANT PRIORITY_THRESHOLD: 5   // only process findings with priority <= 5
CONSTANT MAX_CODE_CHARS: 2000


FUNCTION run_ai_analysis(findings, model):
    eligible <- [f for f in findings WHERE f.priority <= PRIORITY_THRESHOLD]

    IF Ollama NOT reachable at localhost:11434 THEN
        print warning "Ollama offline -- AI step skipped"
        RETURN []
    END IF

    recommendations <- []
    FOR each finding in eligible DO
        rec <- analyze_snippet(finding.code_snippet, finding.vuln_type,
                               finding.iso_controls, finding.file_path,
                               finding.line_start, model)
        recommendations.append(rec)
    END FOR

    print_batch_summary(recommendations)
    RETURN recommendations
END FUNCTION


FUNCTION analyze_snippet(code, vuln_type, iso_controls, file_path,
                         line_start, model):
    truncated <- code[:MAX_CODE_CHARS]

    IF lines(truncated) <= 3 THEN
        prompt <- build_fim_prompt(truncated, vuln_type, iso_controls)
        fim_used <- TRUE
    ELSE
        messages <- build_chat_messages(truncated, vuln_type, iso_controls)
        fim_used <- FALSE
    END IF

    raw_text <- call_ollama_chat(messages, model, temperature=0.1)

    RETURN parse_response(raw_text, truncated, iso_controls, vuln_type,
                          file_path, line_start, fim_used)
END FUNCTION


FUNCTION build_chat_messages(code, vuln_type, iso_controls):
    // Condition A (standard): identical prompt for all models
    system_msg <- "You are a PHP security expert and migration specialist..."
    user_msg   <- "TASK: Analyze [{vuln_type}] vulnerability...
                   VULNERABLE CODE: ```php {code} ```
                   1. Explain the vulnerability.
                   2. Provide corrected PHP 8.x code in a ```php block.
                   Last line: CONFIDENCE: [0-100]"
    RETURN [system_msg, user_msg]
END FUNCTION


FUNCTION build_optimized_chat_messages(code, vuln_type, iso_controls, model):
    // Condition B: per-model optimized prompt
    IF model == "qwen2.5-coder:7b" THEN
        // relaxed format, soft confidence request
    ELSE IF model == "deepseek-coder:6.7b" THEN
        // short and direct, single instruction
    ELSE IF model == "mistral:7b" THEN
        // one-shot example demonstrating expected format
    ELSE IF model == "llama3.1:8b" THEN
        // explicit role-play + 4 numbered steps
    ELSE IF model == "codellama:7b" THEN
        // same as Condition A + php -l syntax validity instruction
    ELSE
        // fallback to standard Condition A
    END IF
    RETURN [system_msg, user_msg]
END FUNCTION


FUNCTION parse_response(raw_text, original_code, iso_controls, ...):
    IF raw_text is empty THEN
        RETURN placeholder_recommendation(confidence=0.0)
    END IF

    // Extract explanation:
    //   try <explanation> XML tag
    //   else try numbered section "1. EXPLANATION:"
    //   else strip code fences from whole text

    // Extract suggested fix (PHP code):
    //   try <fix> XML tag
    //   else try numbered section "2. FIXED CODE:"
    //   else extract ```php ... ``` fenced block

    // Extract confidence score:
    //   try <confidence>N</confidence> XML tag
    //   else try "CONFIDENCE: N" keyword (integer 0-100)
    //   else try decimal 0.x near "confidence"
    //   else try percentage near "confidence"
    //   else try natural-language ("not sure"->0.30, "confident"->0.75, etc.)
    //   else return 0.0 (no data)

    RETURN AIRecommendation(original_code, suggested_fix, explanation,
                            confidence, iso_controls, ...)
END FUNCTION


FUNCTION run_llm_comparison(findings, models, runs_per_finding,
                             prompt_mode, reports_dir):
    eligible <- [f for f in findings WHERE f.priority <= PRIORITY_THRESHOLD]

    report <- {models_compared, runs_per_finding, prompt_mode, findings: []}

    FOR each model in models DO
        IF Ollama NOT reachable THEN
            mark model as unavailable
            CONTINUE
        END IF

        FOR each finding in eligible DO
            IF prompt_mode == "standard" THEN
                messages <- build_chat_messages(finding)   // Condition A
            ELSE
                messages <- build_optimized_chat_messages(finding, model)  // Condition B
            END IF

            confidences <- []
            times       <- []
            FOR run_index = 1 to runs_per_finding DO
                (raw_text, elapsed) <- call_ollama_chat_timed(messages, model)
                confidence <- extract_confidence(raw_text)
                format_ok  <- check_format_valid(raw_text)
                confidences.append(confidence)
                times.append(elapsed)
            END FOR

            finding_result <- {
                confidence_mean:     mean(confidences),
                confidence_variance: variance(confidences),
                confidence_stdev:    stdev(confidences),
                format_compliance_rate: count(format_ok) / runs_per_finding,
                mean_inference_time_sec: mean(times)
            }
            report.append(finding_result)
        END FOR
    END FOR

    save_json(report, reports_dir / "llm_comparison_{timestamp}.json")
    print_comparison_table(report)
    RETURN report
END FUNCTION
```

---

## Modul 6: `iso_mapper.py` — Pemetaan ISO/IEC 27001:2022

```
PROGRAM: ISOMapper

DATA STRUCTURE ISOControl:
    control_id    // e.g. "A.8.28"
    title, description
    status        // COMPLIANT | PARTIAL | NON_COMPLIANT
    findings_count
    evidence      // list of human-readable strings (max 30)

DATA STRUCTURE ISOReport:
    controls:          dict of ISOControl (keyed by control_id)
    overall_status:    worst status among all controls
    total_findings
    critical_findings  // ERROR-severity only
    generated_at

CONSTANT CONTROL_REGISTRY:
    A.5.17  Authentication Information
    A.8.24  Use of Cryptography
    A.8.25  Secure Development Lifecycle
    A.8.26  Application Security Requirements
    A.8.28  Secure Coding
    A.8.29  Security Testing in Development

STATUS RULES:
    NON_COMPLIANT: >= 1 ERROR-severity finding mapped to this control
    PARTIAL:       only WARNING-severity findings (no ERROR)
    COMPLIANT:     no findings mapped to this control


FUNCTION run_iso_mapping(scan_result, analysis_result, ai_recs, output_path):
    // Step 1: Collect (severity, evidence_string) per control
    //         from Semgrep + PHPStan findings
    findings_map <- {}
    FOR each control in CONTROL_REGISTRY DO
        findings_map[control] <- []
    END FOR

    IF scan_result != NULL THEN
        FOR each finding in scan_result.findings DO
            severity <- normalize(finding.severity)  // INFO -> WARNING
            evidence <- "[Semgrep][{vuln_type}] {file}:{line} -- {message}"
            FOR each ctrl in finding.iso_controls DO
                findings_map[ctrl].append((severity, evidence))
            END FOR
        END FOR
    END IF

    IF analysis_result != NULL THEN
        FOR each error in analysis_result.errors DO
            IF error.file_path == "<phpstan>" THEN CONTINUE END IF
            evidence <- "[PHPStan] {file}:{line} -- {message}"
            FOR each ctrl in error.iso_controls DO
                findings_map[ctrl].append((severity, evidence))
            END FOR
        END FOR
    END IF

    // Step 2: Collect AI fix evidence (info only, does NOT affect status)
    ai_evidence_map <- {}
    FOR each rec in ai_recs DO
        evidence <- "[AI/{model}][{vuln_type}] {file}:{line} -- fix suggested ({confidence})"
        FOR each ctrl in rec.iso_controls DO
            ai_evidence_map[ctrl].append(evidence)
        END FOR
    END FOR

    // Step 3: Build ISOControl per control
    controls <- {}
    FOR each (ctrl_id, title, description) in CONTROL_REGISTRY DO
        entries  <- findings_map[ctrl_id]
        ai_evs   <- ai_evidence_map[ctrl_id]

        status   <- determine_status(entries)
        evidence <- (ERROR entries + WARNING entries + ai_evs)[:30]

        controls[ctrl_id] <- ISOControl(ctrl_id, title, description,
                                        status, count(entries), evidence)
    END FOR

    // Step 4: Overall status = worst status among all controls
    overall_status <- max(ctrl.status for ctrl in controls)

    // Step 5: Totals (Semgrep + PHPStan, no double-counting)
    total_findings    <- scan.total + analysis.total
    critical_findings <- scan.ERROR_count + analysis.ERROR_count

    report <- ISOReport(controls, overall_status, total_findings,
                        critical_findings, now())

    print_control_table(report)
    save_json(report, output_path)
    RETURN report
END FUNCTION


FUNCTION determine_status(entries):
    severities <- {sev for (sev, _) in entries}
    IF "ERROR" in severities   THEN RETURN NON_COMPLIANT END IF
    IF "WARNING" in severities THEN RETURN PARTIAL       END IF
    RETURN COMPLIANT
END FUNCTION
```

---

## Modul 7: `composer_analyzer.py` — Analisis Dependensi Composer

```
PROGRAM: ComposerAnalyzer

DATA STRUCTURE DependencyRecommendation:
    package
    current_version_constraint
    status      // "safe" | "upgrade" | "replace" | "manual_review"
    suggestion
    iso_control // "A.8.25"

DATA STRUCTURE ComposerAnalysisResult:
    composer_found: bool
    php_constraint           // e.g. ">=7.4" from composer.json
    recommendations: list of DependencyRecommendation
    issues_count             // count where status != "safe"

CONSTANT KNOWN_PACKAGES:
    phpoffice/phpexcel      -> replace  with phpoffice/phpspreadsheet
    dompdf/dompdf           -> upgrade  to >=2.0 for PHP 8.x
    swiftmailer/swiftmailer -> replace  with symfony/mailer
    codeigniter/framework   -> replace  with codeigniter4/framework
    guzzlehttp/guzzle       -> upgrade  to >=7.0
    monolog/monolog         -> safe     (>=2.0 supports PHP 8.x)
    firebase/php-jwt        -> safe     (>=6.0 supports PHP 8.x)
    ... (and others)


FUNCTION run_composer_analysis(input_dir, target_php):
    composer_path <- input_dir / "composer.json"

    IF composer_path does NOT exist THEN
        RETURN ComposerAnalysisResult(composer_found=FALSE)
    END IF

    data <- parse_json(composer_path)

    php_constraint <- data["require"]["php"]   // e.g. ">=7.4 <8.0"

    // Collect all dependencies (require + require-dev),
    // excluding "php" and "ext-*" meta entries
    deps <- merge(data["require"], data["require-dev"])
    deps <- filter(deps, exclude php and ext-*)

    recommendations <- []
    FOR each (package, version) in deps DO
        rec <- evaluate_package(package, version, target_php)
        recommendations.append(rec)
    END FOR

    print_dependency_table(recommendations)
    RETURN ComposerAnalysisResult(composer_found=TRUE, php_constraint,
                                  recommendations)
END FUNCTION


FUNCTION evaluate_package(package, version, target_php):
    IF package in KNOWN_PACKAGES THEN
        (action, suggestion, php8_safe) <- KNOWN_PACKAGES[package]
        status <- "safe" IF php8_safe ELSE action
    ELSE
        status     <- "manual_review"
        suggestion <- "No known PHP 8.x data for '{package}'. Verify manually."
    END IF

    RETURN DependencyRecommendation(package, version, status, suggestion)
END FUNCTION
```

---

## Ringkasan Alur Pipeline

```
INPUT: PHP source files (PHP 5.x / 7.x) in input/

Step 1  run_scan(input/)         -> ScanResult  [Semgrep, pre-conversion]
Step 2  run_conversion(input/, output/)  -> ConversionResult  [Rector]
Step 2b run_composer_analysis(input/)    -> ComposerAnalysisResult
Step 3  run_scan(output/)        -> ScanResult  [Semgrep, post-conversion]
Step 4  run_analysis(output/)    -> AnalysisResult  [PHPStan]
Step 5  run_ai_analysis(pre_scan.findings)  -> list[AIRecommendation]  [Ollama LLM]
   OR   run_llm_comparison(pre_scan.findings, 5_models, 3_runs)
Step 6  run_iso_mapping(pre_scan, analysis, ai_recs) -> ISOReport

OUTPUT:
  output/          -- PHP 8.x converted files
  reports/
    iso_report_{timestamp}.json
    pipeline_result_{timestamp}.json
    llm_comparison_{timestamp}.json   (if --compare-all)

EXIT CODE:
  0 -- ISO overall_status == COMPLIANT
  1 -- NON_COMPLIANT or PARTIAL or pipeline stage failed
```
