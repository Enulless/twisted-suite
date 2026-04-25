---
step_id: wp_stress.phase1.baseline_ab
procedure: wp_stress
stage: phase1
title: Baseline performance with Apache Bench
estimated_minutes: 8
---

## Why

Pre-engagement setup prevents uncontrolled testing, ensures you can distinguish attack-induced anomalies from baseline noise, and gives you a clean rollback point if the site is damaged during testing.

## How

Confirm target scope

a. Record the exact domain(s) and IP(s) in scope. Example: mysite.example.com / 203.0.113.10

b. Verify you are the registrant or have written authorization on file.

c. Notify your hosting provider if your plan prohibits stress testing (many shared hosts do).

Create a full site backup

a. Use your hosting control panel (cPanel / Plesk) or a plugin like UpdraftPlus to generate a complete backup (files + database).

b. Download the backup to a local machine or off-site storage.

c. Record backup timestamp and file hash (SHA-256).

Record baseline performance metrics

a. Run: ab -n 100 -c 5 https://yoursite.com/  and save the output.

b. Note: requests/sec, mean response time, 99th percentile latency, error rate.

c. Screenshot server resource utilization (CPU, RAM, DB connections) at rest.

Enable verbose server logging

a. SSH into server and confirm Apache/Nginx access and error logs are active.

b. Enable PHP error logging: set display_errors = Off, log_errors = On in php.ini.

c. Enable slow query log in MySQL: set slow_query_log = ON, long_query_time = 1.

Open a live resource monitor

a. SSH session 1: run htop or top to watch CPU and memory in real time.

b. SSH session 2: run tail -f /var/log/apache2/error.log (or nginx equivalent).

c. SSH session 3: run tail -f /var/log/mysql/slow.log for database monitoring.

All data collected here is your control group. Every finding from Phases 2 and 3 will be compared against this baseline to determine what is anomalous or newly exposed.

## What to Collect

Baseline ab output (saved to baseline_ab.txt)

Screenshot of server resources at rest

Backup file path, timestamp, and SHA-256 hash

PHP.ini and MySQL config snapshots
