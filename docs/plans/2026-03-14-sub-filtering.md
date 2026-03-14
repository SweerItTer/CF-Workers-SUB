# Subscription Filtering Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add conservative, configurable subscription filtering to CF-Workers-SUB without changing main.

**Architecture:** Introduce a post-processing pipeline for plaintext node lines before dedupe/output and a Clash YAML proxy filter after conversion. Rules come from env/query params with safe defaults. Keep implementation self-contained in `_worker.js`.

**Tech Stack:** Cloudflare Workers JavaScript, lightweight inline tests with Node.

---

### Task 1: Add failing tests for filtering behavior
**Files:**
- Create: `tests/filter.test.js`
- Create: `tests/run-tests.js`
- Modify: `_worker.js`

### Task 2: Implement plaintext node filtering and sorting
**Files:**
- Modify: `_worker.js`

### Task 3: Implement Clash YAML proxy filtering
**Files:**
- Modify: `_worker.js`

### Task 4: Add config parsing for env/query controls
**Files:**
- Modify: `_worker.js`
- Modify: `README.md`

### Task 5: Run tests and verify sample behavior
**Files:**
- Modify: none
