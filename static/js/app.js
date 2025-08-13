// ...existing code...

// ...existing code...

// (Place this after all DOM assignments and event listeners)
window.addEventListener('DOMContentLoaded', function() {
  const customFileBtn = document.getElementById("custom-file-btn");
  const fileUpload = document.getElementById("file-upload");
  if (customFileBtn && fileUpload) {
    customFileBtn.addEventListener("click", () => fileUpload.click());
    fileUpload.addEventListener("change", () => {
      if (fileUpload.files.length > 0) {
        customFileBtn.textContent = `📁 ${fileUpload.files[0].name}`;
      } else {
        customFileBtn.textContent = "📁 Upload Emails";
      }
    });
  }
});
// Initialize Socket.IO connection (loaded from CDN in HTML)
const socket = io();

// Global variables
let currentResults = []
let isScanning = false
let currentBatchId = null

// DOM elements
const singleEmailInput = document.getElementById("single-email")
const scanSingleBtn = document.getElementById("scan-single-btn")
const singleResult = document.getElementById("single-result")
const batchEmailsTextarea = document.getElementById("batch-emails")
const scanBatchBtn = document.getElementById("scan-batch-btn")
const fileUpload = document.getElementById("file-upload")
const progressContainer = document.getElementById("progress-container")
const progressFill = document.getElementById("progress-fill")
const progressText = document.getElementById("progress-text")
const etaText = document.getElementById("eta-text")
const pauseBtn = document.getElementById("pause-btn")
const resumeBtn = document.getElementById("resume-btn")
const cancelBtn = document.getElementById("cancel-btn")
const cleanCount = document.getElementById("clean-count")
const compromisedCount = document.getElementById("compromised-count")
const errorCount = document.getElementById("error-count")
const batchResults = document.getElementById("batch-results")
const exportControls = document.getElementById("export-controls")
const exportSelector = document.getElementById("export-selector")
const showStatsBtn = document.getElementById("show-stats-btn")
const statsModal = document.getElementById("stats-modal")
const closeStats = document.getElementById("close-stats")
const statsContent = document.getElementById("stats-content")

// Event listeners
scanSingleBtn.addEventListener("click", scanSingleEmail)
scanBatchBtn.addEventListener("click", startBatchScan)
fileUpload.addEventListener("change", handleFileUpload)
pauseBtn.addEventListener("click", () => controlBatch("pause"))
resumeBtn.addEventListener("click", () => controlBatch("resume"))
cancelBtn.addEventListener("click", () => controlBatch("stop"))
// Export results with selected type
const exportTypeSelect = document.getElementById("export-type");
exportSelector.addEventListener("click", async () => {
  if (currentResults.length === 0) {
    showNotification("No results to export", "warning");
    return;
  }
  const type = exportTypeSelect ? exportTypeSelect.value : "csv";
  exportSelector.disabled = true;
  exportSelector.textContent = "Exporting...";
  try {
    const response = await fetch("/export-results", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format: type, results: currentResults }),
    });
    const result = await response.json();
    if (result.filename) {
      // Offer download
      const downloadLink = document.createElement("a");
      downloadLink.href = `/download/${result.filename}`;
      downloadLink.download = result.filename;
      downloadLink.style.display = "none";
      document.body.appendChild(downloadLink);
      downloadLink.click();
      document.body.removeChild(downloadLink);
  showNotification(`${type.toUpperCase()} export completed: ${result.filename}`, "success", 5000);
    } else {
      showNotification("Export failed", "error");
    }
  } catch (error) {
    showNotification("Export error", "error");
  } finally {
    exportSelector.disabled = false;
    exportSelector.textContent = "📥 Export Results";
  }
});
showStatsBtn.addEventListener("click", showStatistics)
closeStats.addEventListener("click", () => (statsModal.style.display = "none"))

// Socket.IO event listeners
socket.on("scan_progress", updateProgress)
socket.on("scan_result", addResult)
socket.on("batch_complete", onBatchComplete)
socket.on("scan_error", onScanError)

// Single email scan
async function scanSingleEmail() {
  const email = singleEmailInput.value.trim()

  if (!email) {
    showNotification("Please enter an email address", "warning")
    return
  }

  if (!isValidEmail(email)) {
    showNotification("Please enter a valid email address", "error")
    return
  }

  scanSingleBtn.disabled = true
  scanSingleBtn.textContent = "Scanning..."
  singleResult.innerHTML = '<div class="loading">Checking email...</div>'

  try {
    const response = await fetch("/scan-single", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email: email }),
    })

    const result = await response.json()

    if (response.ok) {
      displaySingleResult(result)
      showNotification(`Scan completed for ${email}`, "success")
    } else {
      singleResult.innerHTML = `<div class="error">Error: ${result.error}</div>`
      showNotification(result.error, "error")
    }
  } catch (error) {
    singleResult.innerHTML = `<div class="error">Network error: ${error.message}</div>`
    showNotification("Network error occurred", "error")
  } finally {
    scanSingleBtn.disabled = false
    scanSingleBtn.textContent = "Scan Email"
  }
}

// Display single scan result
function displaySingleResult(result) {
  const statusClass = result.status === "clean" ? "clean" : result.status === "compromised" ? "compromised" : "error";

  let html = `
        <div class="result-item ${statusClass}">
            <div class="result-header">
                <span class="email">${result.email || ""}</span>
                <span class="status ${statusClass}">${result.status ? result.status.toUpperCase() : ""}</span>
            </div>
    `;

  if (result.status === "compromised") {
    const breaches = Array.isArray(result.breaches) ? result.breaches : [];
    html += `
            <div class="result-details">
                <div class="severity severity-${result.severity}">${result.severity ? result.severity.toUpperCase() : ""} RISK</div>
                <div class="breach-count">${result.breach_count || 0} breach(es) found</div>
                ${result.paste_count > 0 ? `<div class="paste-count">${result.paste_count} paste(s) found</div>` : ""}
                <div class="breaches-list">
                    <h4>Breaches:</h4>
                    ${breaches
                      .map(
                        (breach) => `
                        <div class="breach-item">
                            <strong>${breach.Name || "Unknown"}</strong>
                            <span class="breach-date">${breach.BreachDate ? new Date(breach.BreachDate).getFullYear() : ""}</span>
                            <div class="data-classes">${Array.isArray(breach.DataClasses) ? breach.DataClasses.join(", ") : ""}</div>
                        </div>
                    `
                      )
                      .join("")}
                </div>
            </div>
        `;
  } else if (result.status === "clean") {
    html += '<div class="result-details">No breaches found - this email appears to be safe!</div>';
  } else if (result.status === "error") {
    html += `<div class="result-details error">Error: ${result.error}</div>`;
  }

  html += "</div>";
  singleResult.innerHTML = html
}

// Start batch scan
async function startBatchScan() {
  const emailsText = batchEmailsTextarea.value.trim()

  if (!emailsText) {
    showNotification("Please enter email addresses or upload a file", "warning")
    return
  }

  const emails = emailsText
    .split("\n")
    .map((email) => email.trim())
    .filter((email) => email)

  if (emails.length === 0) {
    showNotification("No valid emails found", "warning")
    return
  }

  if (emails.length > 1000) {
    showNotification("Maximum 1000 emails allowed per batch", "warning")
    return
  }

  try {
    const response = await fetch("/scan-batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ emails: emails }),
    })

    const result = await response.json()

    if (response.ok) {
      currentBatchId = result.batch_id
      isScanning = true
      currentResults = []

      // Show progress container
      progressContainer.style.display = "block"
      batchResults.innerHTML = ""
      exportControls.style.display = "none"

      // Update UI
      scanBatchBtn.disabled = true
      scanBatchBtn.textContent = "Scanning..."

      showNotification(`Batch scan started with ${result.total_emails} emails`, "success")
    } else {
      showNotification(result.error, "error")
    }
  } catch (error) {
    showNotification("Failed to start batch scan", "error")
  }
}

// Handle file upload
function handleFileUpload(event) {
  const file = event.target.files[0]
  if (!file) return

  const reader = new FileReader()
  reader.onload = (e) => {
    const content = e.target.result
    let emails = []

    if (file.name.endsWith(".csv")) {
      // Simple CSV parsing - assumes emails are in first column or one per line
      emails = content.split("\n").map((line) => {
        const firstColumn = line.split(",")[0].trim()
        return firstColumn.replace(/['"]/g, "")
      })
    } else {
      // Text file - one email per line
      emails = content.split("\n").map((email) => email.trim())
    }

    emails = emails.filter((email) => email && isValidEmail(email))
    batchEmailsTextarea.value = emails.join("\n")

    showNotification(`Loaded ${emails.length} emails from file`, "success")
  }

  reader.readAsText(file)
}

// Control batch processing
async function controlBatch(action) {
  try {
    const response = await fetch("/batch-control", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ action: action }),
    })

    const result = await response.json()

    if (response.ok) {
      if (action === "pause") {
        pauseBtn.style.display = "none"
        resumeBtn.style.display = "inline-block"
      } else if (action === "resume") {
        pauseBtn.style.display = "inline-block"
        resumeBtn.style.display = "none"
      } else if (action === "stop") {
        isScanning = false
        progressContainer.style.display = "none"
        scanBatchBtn.disabled = false
        scanBatchBtn.textContent = "Start Batch Scan"
      }

      showNotification(result.message, "success")
    } else {
      showNotification(result.error, "error")
    }
  } catch (error) {
    showNotification("Failed to control batch scan", "error")
  }
}

// Update progress display
function updateProgress(progress) {
  const percentage = progress.total > 0 ? (progress.completed / progress.total) * 100 : 0

  progressFill.style.width = `${percentage}%`
  progressText.textContent = `${progress.completed}/${progress.total} emails scanned`

  if (progress.current_email) {
    progressText.textContent += ` - Currently: ${progress.current_email}`
  }

  // Update ETA
  if (progress.estimated_completion) {
    const eta = new Date(progress.estimated_completion)
    const now = new Date()
    const remaining = Math.max(0, Math.ceil((eta - now) / 1000))

    if (remaining > 0) {
      const minutes = Math.floor(remaining / 60)
      const seconds = remaining % 60
      etaText.textContent = `ETA: ${minutes}m ${seconds}s`
    } else {
      etaText.textContent = "Almost done..."
    }
  }

  // Update status indicators
  if (progress.status === "paused") {
    progressText.textContent += " (PAUSED)"
    pauseBtn.style.display = "none"
    resumeBtn.style.display = "inline-block"
  } else if (progress.status === "running") {
    pauseBtn.style.display = "inline-block"
    resumeBtn.style.display = "none"
  }
}

// Add result to display
function addResult(result) {
  currentResults.push(result)

  // Update counters
  const clean = currentResults.filter((r) => r.status === "clean").length
  const compromised = currentResults.filter((r) => r.status === "compromised").length
  const errors = currentResults.filter((r) => r.status === "error").length

  cleanCount.textContent = clean
  compromisedCount.textContent = compromised
  errorCount.textContent = errors

  // Add result to display
  const resultElement = createResultElement(result)
  batchResults.appendChild(resultElement)

  // Auto-scroll to latest result
  resultElement.scrollIntoView({ behavior: "smooth", block: "nearest" })
}

// Create result element
function createResultElement(result) {
  const div = document.createElement("div")
  div.className = `result-item ${result.status}`

  let html = `
        <div class="result-header">
            <span class="email">${result.email}</span>
            <span class="status ${result.status}">${result.status.toUpperCase()}</span>
        </div>
    `

  if (result.status === "compromised") {
    html += `
            <div class="result-details">
                <div class="severity severity-${result.severity}">${result.severity.toUpperCase()} RISK</div>
                <div class="breach-summary">${result.breach_count} breach(es)${result.paste_count > 0 ? `, ${result.paste_count} paste(s)` : ""}</div>
                <div class="breach-names">${result.breaches.map((b) => b.Name).join(", ")}</div>
            </div>
        `
  } else if (result.status === "error") {
    html += `<div class="result-details error">${result.error}</div>`
  }

  div.innerHTML = html
  return div
}

// Handle batch completion
function onBatchComplete(data) {
  isScanning = false
  progressContainer.style.display = "none"
  exportControls.style.display = "flex"

  scanBatchBtn.disabled = false
  scanBatchBtn.textContent = "Start Batch Scan"

  showNotification(`Batch scan completed! ${data.total_results} emails processed`, "success", 5000)
}

// Handle scan errors
function onScanError(error) {
  showNotification(`Scan error: ${error.error}`, "error")
  isScanning = false
  progressContainer.style.display = "none"
  scanBatchBtn.disabled = false
  scanBatchBtn.textContent = "Start Batch Scan"
}

// Show export format selector
async function showExportFormatSelector() {
  if (currentResults.length === 0) {
    showNotification("No results to export", "warning")
    return
  }

  try {
    const response = await fetch("/export-formats")
    const formats = await response.json()

    const modal = document.createElement("div")
    modal.className = "modal"
    modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Select Export Format</h3>
                    <button class="btn btn-close" onclick="closeExportModal()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="format-grid">
                        ${Object.entries(formats)
                          .map(
                            ([key, format]) => `
                            <div class="format-card ${format.available ? "" : "disabled"}" 
                                 ${format.available ? `onclick="exportResults('${key}')"` : ""}>
                                <div class="format-icon">${getFormatIcon(key)}</div>
                                <div class="format-name">${format.name}</div>
                                <div class="format-description">${format.description}</div>
                                ${!format.available ? '<div class="format-unavailable">Not Available</div>' : ""}
                            </div>
                        `,
                          )
                          .join("")}
                    </div>
                </div>
            </div>
        `

    document.body.appendChild(modal)
    modal.style.display = "flex"
  } catch (error) {
    showNotification("Failed to load export formats", "error")
  }
}

// Export results
async function exportResults(format) {
  const modal = document.createElement("div")
  modal.className = "modal"
  modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Export Options - ${format.toUpperCase()}</h3>
                <button class="btn btn-close" onclick="closeExportModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="export-options">
                    <div class="option-group">
                        <h4>Filter Options</h4>
                        <label class="checkbox-label">
                            <input type="checkbox" id="exclude-clean"> Exclude clean emails
                        </label>
                        <label class="checkbox-label">
                            <input type="checkbox" id="only-high-severity"> Only high/critical severity
                        </label>
                    </div>
                    
                    <div class="option-group">
                        <h4>Export Information</h4>
                        <div class="export-info">
                            <div class="info-row">
                                <span>Total Results:</span>
                                <span id="total-results">${currentResults.length}</span>
                            </div>
                            <div class="info-row">
                                <span>Compromised:</span>
                                <span id="compromised-results">${currentResults.filter((r) => r.status === "compromised").length}</span>
                            </div>
                            <div class="info-row">
                                <span>Clean:</span>
                                <span id="clean-results">${currentResults.filter((r) => r.status === "clean").length}</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="modal-actions">
                    <button class="btn btn-secondary" onclick="closeExportModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="performExport('${format}')">
                        <span class="export-icon">📥</span> Export ${format.toUpperCase()}
                    </button>
                </div>
            </div>
        </div>
    `

  document.body.appendChild(modal)
  modal.style.display = "flex"

  // Add event listeners for real-time preview
  const excludeClean = modal.querySelector("#exclude-clean")
  const onlyHighSeverity = modal.querySelector("#only-high-severity")

  const updatePreview = () => {
    let filteredResults = currentResults

    if (excludeClean.checked) {
      filteredResults = filteredResults.filter((r) => r.status !== "clean")
    }

    if (onlyHighSeverity.checked) {
      filteredResults = filteredResults.filter((r) => r.severity === "high" || r.severity === "critical")
    }

    modal.querySelector("#total-results").textContent = filteredResults.length
    modal.querySelector("#compromised-results").textContent = filteredResults.filter(
      (r) => r.status === "compromised",
    ).length
    modal.querySelector("#clean-results").textContent = filteredResults.filter((r) => r.status === "clean").length
  }

  excludeClean.addEventListener("change", updatePreview)
  onlyHighSeverity.addEventListener("change", updatePreview)
}

// Perform export
async function performExport(format) {
  const modal = document.querySelector(".modal")
  const excludeClean = modal.querySelector("#exclude-clean").checked
  const onlyHighSeverity = modal.querySelector("#only-high-severity").checked

  const exportButton = modal.querySelector(".btn-primary")
  const originalText = exportButton.innerHTML
  exportButton.innerHTML = '<span class="loading"></span> Exporting...'
  exportButton.disabled = true

  try {
    const response = await fetch("/export-results", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        format: format,
        results: currentResults,
        options: {
          exclude_clean: excludeClean,
          only_high_severity: onlyHighSeverity,
        },
      }),
    })

    const result = await response.json()

    if (result.filename) {
      showNotification(`${format.toUpperCase()} export completed: ${result.filename}`, "success", 5000)

      // Offer download
      const downloadLink = document.createElement("a")
      downloadLink.href = `/download/${result.filename}`
      downloadLink.download = result.filename
      downloadLink.style.display = "none"
      document.body.appendChild(downloadLink)
      downloadLink.click()
      document.body.removeChild(downloadLink)

      closeExportModal()
    } else {
      showNotification("Export completed but no file generated", "warning")
    }
  } catch (error) {
    showNotification("Failed to export results", "error")
  } finally {
    exportButton.innerHTML = originalText
    exportButton.disabled = false
  }
}

// Close export modal
function closeExportModal() {
  const modal = document.querySelector(".modal")
  if (modal) {
    modal.remove()
  }
}

// Show statistics
async function showStatistics() {
  if (currentResults.length === 0) {
    showNotification("No results available", "warning")
    return
  }

  try {
    const response = await fetch("/batch-results")
    const data = await response.json()
    const stats = data.statistics

    let html = `
            <div class="stats-grid">
                <div class="stat-card">
                    <h4>Overview</h4>
                    <div class="stat-row">
                        <span>Total Emails:</span>
                        <span>${stats.total_emails || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span>Clean:</span>
                        <span class="clean">${stats.clean_emails || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span>Compromised:</span>
                        <span class="compromised">${stats.compromised_emails || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span>Errors:</span>
                        <span class="error">${stats.error_emails || 0}</span>
                    </div>
                </div>
                
                <div class="stat-card">
                    <h4>Breach Details</h4>
                    <div class="stat-row">
                        <span>Total Breaches:</span>
                        <span>${stats.total_breaches || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span>Total Pastes:</span>
                        <span>${stats.total_pastes || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span>Processing Time:</span>
                        <span>${stats.processing_time ? `${stats.processing_time.toFixed(1)}s` : "N/A"}</span>
                    </div>
                </div>
            </div>
        `

    if (stats.severity_breakdown && Object.keys(stats.severity_breakdown).length > 0) {
      html += `
                <div class="stat-card">
                    <h4>Severity Breakdown</h4>
                    ${Object.entries(stats.severity_breakdown)
                      .map(
                        ([severity, count]) => `
                        <div class="stat-row">
                            <span class="severity-${severity}">${severity.toUpperCase()}:</span>
                            <span>${count}</span>
                        </div>
                    `,
                      )
                      .join("")}
                </div>
            `
    }

    if (stats.top_breaches && Object.keys(stats.top_breaches).length > 0) {
      html += `
                <div class="stat-card">
                    <h4>Most Common Breaches</h4>
                    ${Object.entries(stats.top_breaches)
                      .slice(0, 5)
                      .map(
                        ([breach, count]) => `
                        <div class="stat-row">
                            <span>${breach}:</span>
                            <span>${count}</span>
                        </div>
                    `,
                      )
                      .join("")}
                </div>
            `
    }

    statsContent.innerHTML = html
    statsModal.style.display = "flex"
  } catch (error) {
    showNotification("Failed to load statistics", "error")
  }
}

// Utility functions
function isValidEmail(email) {
  const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
  return pattern.test(email)
}

function getFormatIcon(format) {
  const icons = {
    json: "📄",
    csv: "📊",
    excel: "📈",
    pdf: "📋",
    zip: "📦",
  }
  return icons[format] || "📄"
}

function showNotification(message, type = "info", duration = 3000) {
  const container = document.getElementById("notification-container") || document.body

  const notification = document.createElement("div")
  notification.className = `notification ${type}`
  notification.innerHTML = `
        <span class="notification-message">${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">&times;</button>
    `

  container.appendChild(notification)

  // Auto-remove after duration
  setTimeout(() => {
    if (notification.parentElement) {
      notification.remove()
    }
  }, duration)
}

// Initialize app
document.addEventListener("DOMContentLoaded", () => {
  console.log("Email Breach Scanner initialized")

  // Check for any existing batch status on page load
  fetch("/batch-status")
    .then((response) => response.json())
    .then((data) => {
      if (data.is_processing) {
        isScanning = true
        progressContainer.style.display = "block"
        scanBatchBtn.disabled = true
        scanBatchBtn.textContent = "Scanning..."

        if (data.progress) {
          updateProgress(data.progress)
        }
      }
    })
    .catch((error) => {
      console.log("No existing batch found")
    })
})
