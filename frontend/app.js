// ============================================================
// AUTHENTICATION & GLOBAL CONFIG
// ============================================================

const API = (() => {
    const params = new URLSearchParams(window.location.search || "");
    const customApi = params.get("api");
    if (customApi) {
        return customApi.replace(/\/+$/, "");
    }
    if (window.location.protocol === "file:") {
        return "http://127.0.0.1:8000/api";
    }
    const devStaticPorts = new Set(["5500", "5501", "3000", "5173", "4200", "8080"]);
    if (devStaticPorts.has(window.location.port)) {
        const host = window.location.hostname || "127.0.0.1";
        return `http://${host}:8000/api`;
    }
    return "/api";
})();
const TOKEN_KEY = "cyber_digital_twin_access_token";

const ROLE_KEY =
    "cyber_digital_twin_user_role";


let currentUserRole = null;


function getUserRole() {

    return sessionStorage.getItem(
        ROLE_KEY
    );

}


function saveUserRole(
    role
) {

    sessionStorage.setItem(
        ROLE_KEY,
        role
    );

    currentUserRole =
        role;

}


function clearUserRole() {

    sessionStorage.removeItem(
        ROLE_KEY
    );

    currentUserRole =
        null;

}


function decodeJwtPayload(
    token
) {

    try {

        const payload =
            token.split(".")[1];


        const normalized =
            payload
                .replace(/-/g, "+")
                .replace(/_/g, "/");


        const decoded =
            atob(
                normalized
            );


        return JSON.parse(
            decoded
        );

    }

    catch (error) {

        console.error(
            "JWT PAYLOAD DECODE ERROR:",
            error
        );


        return null;

    }

}

let refreshIntervals = [];
let currentFleetHost = "localhost";


let dashboardInitialized = false;

function getAccessToken() {

    return sessionStorage.getItem(
        TOKEN_KEY
    );

}


function saveAccessToken(
    token
) {

    sessionStorage.setItem(
        TOKEN_KEY,
        token
    );

}


function clearAccessToken() {

    sessionStorage.removeItem(
        TOKEN_KEY
    );

}


function lockDashboard() {

    document.body.classList.add(
        "auth-locked"
    );


    const loginScreen =
        document.getElementById(
            "loginScreen"
        );


    if (loginScreen) {

        loginScreen.style.display =
            "flex";

    }

}

function unlockDashboard() {

    document.body.classList.remove(
        "auth-locked"
    );


    const loginScreen =
        document.getElementById(
            "loginScreen"
        );


    if (loginScreen) {

        loginScreen.style.display =
            "none";

    }

}

function showLoginMessage(
    message
) {

    const element =
        document.getElementById(
            "loginMessage"
        );

    if (!element) {
        return;
    }

    element.textContent =
        message;

}

async function logout() {

    const token = getAccessToken();

    // Revoke the token on the backend
    if (token) {

        try {

            await fetch(
                `${API}/auth/logout`,
                {
                    method: "POST",
                    headers: {
                        "Authorization": `Bearer ${token}`
                    }
                }
            );

        }

        catch (error) {

            console.error(
                "Server logout request failed:",
                error
            );

        }

    }

    // Clear the browser session
    clearAccessToken();

    clearUserRole();

    refreshIntervals.forEach(
        (intervalId) => {
            clearInterval(intervalId);
        }
    );

    refreshIntervals = [];

    const logoutContainer =
        document.getElementById("logoutContainer");

    if (logoutContainer) {
        logoutContainer.remove();
    }

    dashboardInitialized = false;

    lockDashboard();

    showLoginMessage(
        "Session ended. Please login again."
    );
}

async function apiFetch(
    url,
    options = {}
) {

    const token =
        getAccessToken();


    const headers = new Headers(
        options.headers || {}
    );


    if (token) {

        headers.set(
            "Authorization",
            `Bearer ${token}`
        );

    }


    const resolvedUrl = (
        typeof url === "string" &&
        url.startsWith("/") &&
        !url.startsWith(`${API}/`) &&
        url !== API &&
        !url.startsWith("/api/")
    )
        ? `${API}${url}`
        : url;

    const response =
        await fetch(
            resolvedUrl,
            {
                ...options,
                headers
            }
        );


    if (response.status === 401) {

        logout();

        throw new Error(
            "Authentication required"
        );

    }


    return response;

}


async function login(
    username,
    password
) {

    let response;
    try {
        response =
            await fetch(
                `${API}/auth/login`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify(
                        {
                            username,
                            password
                        }
                    )
                }
            );
    } catch (networkErr) {
        throw new Error(
            `Cannot connect to backend API (${API}). Verify the server is running.`
        );
    }


    const rawText =
        await response.text();

    let data = {};
    if (rawText) {
        try {
            data = JSON.parse(rawText);
        } catch (parseErr) {
            data = {
                detail: rawText.slice(0, 180)
            };
        }
    }


    if (!response.ok) {

        throw new Error(
            data.detail ||
            `Login failed (HTTP ${response.status})`
        );

    }


    if (!data.access_token) {

        throw new Error(
            "Authentication token not received"
        );

    }


saveAccessToken(
    data.access_token
);


const payload =
    decodeJwtPayload(
        data.access_token
    );


if (
    !payload ||
    !payload.role ||
    !payload.exp ||
    payload.exp <= Date.now() / 1000
) {

    clearAccessToken();
    clearUserRole();

    throw new Error(
        "Invalid or expired authentication token."
    );

}

saveUserRole(
    payload.role
);


console.log(
    "Authenticated role:",
    payload.role
);


return data;

}


async function handleLogin(
    event
) {

    event.preventDefault();


    const username =
        document.getElementById(
            "loginUsername"
        ).value.trim();


    const password =
        document.getElementById(
            "loginPassword"
        ).value;


    const button =
        document.getElementById(
            "loginButton"
        );


    if (!username || !password) {

        showLoginMessage(
            "Username and password are required."
        );

        return;

    }


    button.disabled = true;

    button.textContent =
        "Logging in...";


    showLoginMessage(
        ""
    );


    try {

        const data =
            await login(
                username,
                password
            );


        unlockDashboard();


        showLoginMessage(
            ""
        );


        addLogoutButton(
            data.username
        );


        initializeDashboard();


    }

    catch (error) {

        console.error(
            "LOGIN ERROR:",
            error
        );


        clearAccessToken();


        showLoginMessage(
            error.message ||
            "Invalid username or password."
        );

    }

    finally {

        button.disabled = false;

        button.textContent =
            "Login";

    }

}


function addLogoutButton(
    username
) {

    let logoutContainer =
        document.getElementById(
            "logoutContainer"
        );

    // Create the container only if it does not exist
    if (!logoutContainer) {

        logoutContainer =
            document.createElement(
                "div"
            );

        logoutContainer.id =
            "logoutContainer";

        document.body.prepend(
            logoutContainer
        );
    }

    // Always update the current user's identity
    logoutContainer.innerHTML = `

        <span>

            Logged in as:

            <strong>
                ${username}
            </strong>

            &nbsp; | &nbsp;

            Role:

            <strong>
                ${
                    currentUserRole
                        ? currentUserRole.toUpperCase()
                        : "UNKNOWN"
                }
            </strong>

        </span>

        <button
            id="logoutButton"
            type="button"
        >
            Logout
        </button>

    `;

    // Attach logout event listener
    document
        .getElementById(
            "logoutButton"
        )
        .addEventListener(
            "click",
            logout
        );

}

function initializeDashboard() {

    if (dashboardInitialized) {

        console.log(
            "=== DASHBOARD ALREADY INITIALIZED ==="
        );

        return;

    }


    dashboardInitialized = true;

    // ============================================================
// ROLE-BASED FRONTEND VISIBILITY
// ============================================================

const responseSection =
    document.getElementById(
        "securityResponseExecutionSection"
    );

if (responseSection) {

    responseSection.style.display =
        currentUserRole === "admin"
            ? ""
            : "none";

}

    console.log(
        "=== INITIALIZING AUTHENTICATED DASHBOARD ==="
    );

    loadDashboard();

    // Infrastructure health refresh
    loadInfrastructureHealth();

    loadHistory();

    loadAnomalies();

    loadSSHEvents();

    loadSecurityAlerts();

    loadNotificationHistory();

    loadDeliveryHealth();

    loadNotificationSettings();

    loadNotificationSettingsAudit();

    loadNotificationAnalytics();

    // Notification Policy Simulator

    loadNotificationSimulationHistory();

    document.getElementById(
        "runNotificationSimulationButton"
    )?.addEventListener(
        "click",
        runNotificationSimulation
    );

    document.getElementById(
        "refreshNotificationSimulationHistoryButton"
    )?.addEventListener(
        "click",
        loadNotificationSimulationHistory
    );

document.getElementById(
    "analyticsRefreshButton"
)?.addEventListener(
    "click",
    loadNotificationAnalytics
);

document.getElementById(
    "analyticsPeriod"
)?.addEventListener(
    "change",
    loadNotificationAnalytics
);

document.getElementById(
    "analyticsDays"
)?.addEventListener(
    "change",
    loadNotificationAnalytics
);

    loadIncidentReminders();

    loadSecurityIncidents();

    loadSecurityCampaigns();

    loadSecurityResponses();

if (
    currentUserRole === "admin"
) {

    loadResponseExecution();

}
    loadSecurityDecisions();

    loadSecurityResponseAudit();

    loadThreatIntelligence();

    loadMitreCoverage();

    loadPredictiveAnalytics();

    loadFimData();

    loadProcessData();

    loadNetworkData();

    loadFleetData();

    loadSimulationData();

    loadIncidentResponseData();

    startAutoRefresh();


    console.log(
        "=== CYBER DIGITAL TWIN AUTO-REFRESH ENABLED ==="
    );

}


function startAutoRefresh() {

    refreshIntervals.forEach(
        (intervalId) => {

            clearInterval(
                intervalId
            );

        }
    );


    refreshIntervals = [];

    const pollTasks = [
        [loadDashboard, 10000],
        [loadDeliveryHealth, 15000],
        [loadInfrastructureHealth, 15000],
        [loadHistory, 10000],
        [loadAnomalies, 15000],
        [loadSSHEvents, 15000],
        [loadSecurityAlerts, 15000],
        [loadNotificationHistory, 20000],
        [loadIncidentReminders, 15000],
        [loadSecurityIncidents, 15000],
        [loadSecurityCampaigns, 20000],
        [loadSecurityResponses, 20000],
        [loadSecurityResponseAudit, 20000],
        [loadSecurityDecisions, 20000],
        [loadThreatIntelligence, 30000],
        [loadPredictiveAnalytics, 30000],
        [loadFimData, 30000],
        [loadProcessData, 15000],
        [loadNetworkData, 15000],
        [loadFleetData, 30000],
        [loadSimulationData, 30000],
        [loadIncidentResponseData, 30000],
    ];

    if (currentUserRole === "admin") {
        pollTasks.push([loadResponseExecution, 20000]);
    }

    pollTasks.forEach(([fn, delay]) => {
        refreshIntervals.push(setInterval(fn, delay));
    });

}

document.addEventListener(
    "DOMContentLoaded",
    () => {

        lockDashboard();


        const loginForm =
            document.getElementById(
                "loginForm"
            );


        if (loginForm) {

            loginForm.addEventListener(
                "submit",
                handleLogin
            );

        }

        const quickDemoBtn = document.getElementById("quickDemoLoginBtn");
        if (quickDemoBtn) {
            quickDemoBtn.addEventListener("click", () => {
                const uInput = document.getElementById("loginUsername");
                const pInput = document.getElementById("loginPassword");
                if (uInput) uInput.value = "admin";
                if (pInput) pInput.value = "admin123";
                if (loginForm) {
                    if (loginForm.requestSubmit) {
                        loginForm.requestSubmit();
                    } else {
                        loginForm.dispatchEvent(new Event("submit", { cancelable: true }));
                    }
                }
            });
        }


        const existingToken =
            getAccessToken();


        if (existingToken) {

            const payload =
                decodeJwtPayload(existingToken);

            const role =
                payload?.role?.toLowerCase();

            const validRoles = [
                "admin",
                "analyst",
                "viewer"
            ];

if (
    !payload ||
    !validRoles.includes(role) ||
    !payload.exp ||
    payload.exp <= Date.now() / 1000
) {

                logout();
                return;
            }

            saveUserRole(role);

            unlockDashboard();

            addLogoutButton(
                payload.username || payload.sub || "user"
            );

            initializeDashboard();

        }

    }
);

console.log("=== CYBER DIGITAL TWIN APP.JS LOADED ===");

function switchSocTab(tabId) {
    const tabMap = {
        'telemetry': 'dashboard',
        'processes': 'processMonitoringSection',
        'network': 'networkSecuritySection',
        'fim': 'fimMonitoringSection',
        'predictive': 'predictiveAnalyticsSection',
        'simulator': 'attackSimulationSection',
        'playbooks': 'incidentResponseSection',
        'threatintel': 'threatIntelligenceSection',
        'fleet': 'multiHostSection'
    };

    const navButtons = document.querySelectorAll('.soc-nav-bar .nav-tab');
    navButtons.forEach(btn => btn.classList.remove('active'));

    if (window.event && window.event.target) {
        window.event.target.classList.add('active');
    }

    const targetId = tabMap[tabId] || 'dashboard';
    const targetEl = document.getElementById(targetId);
    if (targetEl) {
        targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}
window.switchSocTab = switchSocTab;

let cpuChart;
let memoryChart;
let diskChart;

let notificationEventTrendChart;
let notificationChannelChart;
let notificationSeverityChart;
let incidentDeliveryChart;
let incidentRetryChart;

// ============================================================
// LOAD INFRASTRUCTURE HEALTH
// ============================================================

async function loadInfrastructureHealth() {

    try {

        const response = await apiFetch(
            `${API}/infrastructure/health`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        document.getElementById("infraScore").innerText =
            `${data.health_score}/100`;

        document.getElementById("infraStatus").innerText =
            data.overall_status;

        document.getElementById("infraApi").innerText =
            data.components.api;

        document.getElementById("infraDatabase").innerText =
            data.components.database;

        document.getElementById("infraCollector").innerText =
            data.components.collector;

        const diskMeta = data.components?.controller_disk?.usage_percent;
        document.getElementById("infraDisk").innerText =
            diskMeta !== undefined ? `${diskMeta}% used` : `${data.components?.disk || 'Healthy'}`;

        document.getElementById("infraHosts").innerText =
            Object.entries(data.hosts)
                .map(([name, host]) =>
                    `${name}: ${host.status}`
                )
                .join("\n");

    } catch (error) {

        console.error(
            "INFRASTRUCTURE HEALTH ERROR:",
            error
        );

        document.getElementById("infraStatus").innerText =
            "Connection Error";
    }
}

// ============================================================
// LOAD CURRENT HEALTH
// ============================================================

async function loadDashboard() {

    try {

        const response = await apiFetch(
            `${API}/health`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const server = await response.json();

        document.getElementById("hostname").innerText =
            server.hostname;

        document.getElementById("status").innerText =
            server.status;

        document.getElementById("cpu").innerText =
            `${server.cpu_usage} %`;

        document.getElementById("memory").innerText =
            `${server.memory_usage} %`;

        document.getElementById("disk").innerText =
            `${server.disk_usage} %`;

    } catch (error) {

        console.error("DASHBOARD ERROR:", error);

        document.getElementById("hostname").innerText =
            "Connection Error";

        document.getElementById("status").innerText =
            "Offline";

        document.getElementById("cpu").innerText = "--";
        document.getElementById("memory").innerText = "--";
        document.getElementById("disk").innerText = "--";
    }
}


// ============================================================
// LOAD HISTORICAL DATA
// ============================================================

async function loadHistory() {

    try {

        const response = await apiFetch(
            `${API}/metrics/history?limit=50`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const history = await response.json();

        const orderedHistory = [...history].reverse();

        const labels = orderedHistory.map(
            item =>
                new Date(
                    item.collected_at
                ).toLocaleTimeString()
        );

        const cpuData = orderedHistory.map(
            item => item.cpu_usage
        );

        const memoryData = orderedHistory.map(
            item => item.memory_usage
        );

        const diskData = orderedHistory.map(
            item => item.disk_usage
        );

        updateCharts(
            labels,
            cpuData,
            memoryData,
            diskData
        );

    } catch (error) {

        console.error("HISTORY ERROR:", error);
    }
}


// ============================================================
// LOAD AI ANOMALIES
// ============================================================

async function loadAnomalies() {

    try {

        const response = await apiFetch(
            `${API}/anomalies`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const anomalies = await response.json();

        updateAnomaly(
            "cpuAnomaly",
            anomalies.cpu
        );

        updateAnomaly(
            "memoryAnomaly",
            anomalies.memory
        );

        updateAnomaly(
            "diskAnomaly",
            anomalies.disk
        );

    } catch (error) {

        console.error("ANOMALY ERROR:", error);

        updateAnomalyError("cpuAnomaly");
        updateAnomalyError("memoryAnomaly");
        updateAnomalyError("diskAnomaly");
    }
}


function updateAnomaly(elementId, result) {

    const element =
        document.getElementById(elementId);

    if (!element || !result) {
        return;
    }

    element.className = "anomaly-status";

    if (result.reason) {

        element.innerText =
            result.reason;

        element.classList.add("unknown");

        return;
    }

    if (result.is_anomaly === true) {

        element.innerText =
            "Anomaly";

        element.classList.add("anomaly");

        return;
    }

    if (
        result.score !== undefined &&
        result.score >= 2
    ) {

        element.innerText =
            "Warning";

        element.classList.add("warning");

        return;
    }

    element.innerText =
        "Normal";

    element.classList.add("normal");
}


function updateAnomalyError(elementId) {

    const element =
        document.getElementById(elementId);

    if (!element) {
        return;
    }

    element.innerText =
        "Unavailable";

    element.className =
        "anomaly-status unknown";
}


// ============================================================
// CREATE / UPDATE CHARTS
// ============================================================

function updateCharts(
    labels,
    cpuData,
    memoryData,
    diskData
) {

    if (typeof Chart === "undefined") {
        return;
    }

    if (cpuChart) {
        cpuChart.destroy();
    }

    if (memoryChart) {
        memoryChart.destroy();
    }

    if (diskChart) {
        diskChart.destroy();
    }

    cpuChart = new Chart(
        document.getElementById("cpuChart"),
        {
            type: "line",

            data: {
                labels: labels,

                datasets: [
                    {
                        label: "CPU Usage (%)",
                        data: cpuData,
                        tension: 0.3
                    }
                ]
            },

            options: {
                responsive: true,

                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        }
    );

    memoryChart = new Chart(
        document.getElementById("memoryChart"),
        {
            type: "line",

            data: {
                labels: labels,

                datasets: [
                    {
                        label: "Memory Usage (%)",
                        data: memoryData,
                        tension: 0.3
                    }
                ]
            },

            options: {
                responsive: true,

                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        }
    );

    diskChart = new Chart(
        document.getElementById("diskChart"),
        {
            type: "line",

            data: {
                labels: labels,

                datasets: [
                    {
                        label: "Disk Usage (%)",
                        data: diskData,
                        tension: 0.3
                    }
                ]
            },

            options: {
                responsive: true,

                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        }
    );
}


// ============================================================
// SSH SECURITY EVENTS
// ============================================================

async function loadSSHEvents() {

    try {

        const eventsResponse = await apiFetch(
            `${API}/ssh/events?limit=20`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!eventsResponse.ok) {
            throw new Error(
                `SSH events HTTP ${eventsResponse.status}`
            );
        }

        const events =
            await eventsResponse.json();


        const alertsResponse = await apiFetch(
            `${API}/security/alerts`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!alertsResponse.ok) {
            throw new Error(
                `Security alerts HTTP ${alertsResponse.status}`
            );
        }

        const alerts =
            await alertsResponse.json();


        const alertMap = new Map();

        alerts.forEach(alert => {

            alertMap.set(
                alert.event_id,
                alert
            );

        });


        const table =
            document.getElementById(
                "sshEventsTable"
            );


        if (!table) {
            return;
        }


        let failed = 0;
        let successful = 0;

        events.forEach(event => {

            if (
                event.event_type ===
                "FAILED_LOGIN"
            ) {
                failed++;
            }

            if (
                event.event_type ===
                "SUCCESSFUL_LOGIN"
            ) {
                successful++;
            }

        });


        const failedLogins =
            document.getElementById(
                "failedLogins"
            );

        const successfulLogins =
            document.getElementById(
                "successfulLogins"
            );

        const highRiskEvents =
            document.getElementById(
                "highRiskEvents"
            );

        const criticalEvents =
            document.getElementById(
                "criticalEvents"
            );


        if (failedLogins) {
            failedLogins.textContent = failed;
        }

        if (successfulLogins) {
            successfulLogins.textContent =
                successful;
        }


        const highRiskCount =
            alerts.filter(
                alert =>
                    alert.alert_level === "HIGH"
            ).length;


        const criticalCount =
            alerts.filter(
                alert =>
                    alert.alert_level === "CRITICAL"
            ).length;


        if (highRiskEvents) {
            highRiskEvents.textContent =
                highRiskCount;
        }

        if (criticalEvents) {
            criticalEvents.textContent =
                criticalCount;
        }


        table.innerHTML = "";


        if (events.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="6">
                        No SSH events found
                    </td>
                </tr>
            `;

            return;
        }


        events.forEach(event => {

            const alert =
                alertMap.get(event.id);


            const riskScore =
                alert
                    ? alert.risk_score
                    : "-";


            const riskLevel =
                alert
                    ? alert.alert_level
                    : "-";


            const row =
                document.createElement("tr");


            row.innerHTML = `
                <td>
                    ${new Date(
                        event.event_time
                    ).toLocaleString()}
                </td>

                <td>
                    ${event.event_type}
                </td>

                <td>
                    ${event.username || "-"}
                </td>

                <td>
                    ${event.source_ip || "-"}
                </td>

                <td>
                    ${riskScore}
                </td>

                <td>
                    ${riskLevel}
                </td>
            `;


            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "SSH EVENT ERROR:",
            error
        );
    }
}



// ============================================================
// INCIDENT NOTIFICATION DELIVERY HISTORY
// ============================================================

async function loadNotificationHistory() {

    try {

        const response = await apiFetch(
            `${API}/security/notification-history?limit=50`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const records = await response.json();

        const table = document.getElementById(
            "notificationHistoryTable"
        );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (records.length === 0) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 10;
            cell.textContent = "No notification history available.";

            row.appendChild(cell);
            table.appendChild(row);

            return;
        }

        function formatTime(value) {

            if (!value) {
                return "-";
            }

            const date = new Date(value);

            return Number.isNaN(date.getTime())
                ? "-"
                : date.toLocaleString();
        }

        records.forEach(record => {

            const row = document.createElement("tr");

            const showError =
                currentUserRole === "admin" ||
                currentUserRole === "analyst";

            const values = [
                formatTime(record.created_at),
                record.incident_id,
                record.severity,
                record.priority,
                record.notification_channel,
                record.delivery_status,
                record.attempt_count,
                formatTime(record.last_attempt_at),
                formatTime(record.sent_at),
                showError
                    ? (record.error_message || "-")
                    : "-"
            ];

            values.forEach(value => {

                const cell = document.createElement("td");

                cell.textContent =
                    value === null || value === undefined
                        ? "-"
                        : String(value);

                row.appendChild(cell);

            });

            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "NOTIFICATION HISTORY ERROR:",
            error
        );

    }
}



// ============================================================
// INCIDENT ASSIGNMENT & ACKNOWLEDGEMENT REMINDERS
// ============================================================

async function loadIncidentReminders() {

    const table = document.getElementById(
        "incidentRemindersTable"
    );

    if (!table) {
        return;
    }

    // Viewers do not receive operational reminders.
    if (currentUserRole === "viewer") {

        table.innerHTML = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 9;
        cell.textContent = "No operational reminders available.";

        row.appendChild(cell);
        table.appendChild(row);

        return;
    }

    try {

        const response = await apiFetch(
            `${API}/security/reminders?limit=50`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const records = await response.json();

        table.innerHTML = "";

        if (records.length === 0) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 9;
            cell.textContent = "No incident reminders available.";

            row.appendChild(cell);
            table.appendChild(row);

            return;
        }

        function formatTime(value) {

            if (!value) {
                return "-";
            }

            const date = new Date(value);

            return Number.isNaN(date.getTime())
                ? "-"
                : date.toLocaleString();
        }

        records.forEach(record => {

            const row = document.createElement("tr");

            const values = [
                formatTime(record.created_at),
                record.incident_id,
                record.severity,
                record.reminder_type === "UNASSIGNED"
                    ? "Unassigned Incident"
                    : "Awaiting Acknowledgement",
                record.recipient_username || "-",
                `${record.reminder_after_minutes} minutes`,
                record.reminder_cycle,
                record.delivery_status
            ];

            values.forEach(value => {

                const cell = document.createElement("td");

                cell.textContent =
                    value === null || value === undefined
                        ? "-"
                        : String(value);

                row.appendChild(cell);

            });

            const actionCell = document.createElement("td");

            if (record.delivery_status === "CREATED") {

                const button = document.createElement("button");

                button.type = "button";
                button.textContent = "Mark as Read";
                button.className = "reminder-read-button";

                button.addEventListener("click", async () => {

                    button.disabled = true;
                    button.textContent = "Updating...";

                    try {

                        const readResponse = await apiFetch(
                            `${API}/security/reminders/${record.id}/read`,
                            {
                                method: "POST"
                            }
                        );

                        if (!readResponse.ok) {
                            throw new Error(
                                `HTTP ${readResponse.status}`
                            );
                        }

                        await loadIncidentReminders();

                    } catch (error) {

                        console.error(
                            "MARK REMINDER AS READ ERROR:",
                            error
                        );

                        button.disabled = false;
                        button.textContent = "Retry";

                    }

                });

                actionCell.appendChild(button);

            } else if (record.delivery_status === "READ") {

                actionCell.textContent = "Read";

            } else {

                actionCell.textContent = "-";

            }

            row.appendChild(actionCell);
            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "INCIDENT REMINDER ERROR:",
            error
        );

        table.innerHTML = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 9;
        cell.textContent = "Unable to load incident reminders.";

        row.appendChild(cell);
        table.appendChild(row);

    }

}


// ============================================================
// SECURITY ALERTS
// ============================================================

async function loadSecurityAlerts() {

    try {

        const response =
            await apiFetch(
                `${API}/security/alerts`,
                {
                    method: "GET",
                    mode: "cors",
                    cache: "no-store"
                }
            );


        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }


        const alerts =
            await response.json();


        const table =
            document.getElementById(
                "securityAlertsTable"
            );


        if (!table) {
            return;
        }


        table.innerHTML = "";


        if (alerts.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="6">
                        No security alerts
                    </td>
                </tr>
            `;

            return;
        }


        alerts.forEach(alert => {

            const row =
                document.createElement("tr");


            row.innerHTML = `
                <td>
                    ${new Date(
                        alert.event_time
                    ).toLocaleString()}
                </td>

                <td>
                    ${alert.event_type}
                </td>

                <td>
                    ${alert.username || "-"}
                </td>

                <td>
                    ${alert.source_ip || "-"}
                </td>

                <td>
                    ${alert.risk_score}
                </td>

                <td>
                    ${alert.reason}
                </td>
            `;


            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "SECURITY ALERT ERROR:",
            error
        );
    }
}


// ============================================================
// INCIDENT LIFECYCLE MANAGEMENT — ADMIN ONLY
// ============================================================

function getNextIncidentStatuses(status) {

    const transitions = {
        OPEN: ["INVESTIGATING"],
        INVESTIGATING: ["CONTAINED"],
        CONTAINED: ["RESOLVED"],
        RESOLVED: ["CLOSED"],
        CLOSED: []
    };

    return transitions[
        String(status || "OPEN").toUpperCase()
    ] || [];

}


// ============================================================
// UPDATE INCIDENT LIFECYCLE STATUS
// ============================================================

async function updateIncidentLifecycle(
    incidentId,
    status,
    button
) {

    if (currentUserRole !== "admin") {
        alert("Only administrators can update incident status.");
        return;
    }

    if (!incidentId || !status) {
        alert("Incident ID and status are required.");
        return;
    }

    try {

        if (button) {
            button.disabled = true;
            button.textContent = "Updating...";
        }

        const params = new URLSearchParams({
            status: status,
            notes: "Incident status updated from dashboard by admin"
        });

        const response = await apiFetch(
            `${API}/security/incidents/${encodeURIComponent(incidentId)}/status?${params.toString()}`,
            {
                method: "POST"
            }
        );

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(
                data.detail || `HTTP ${response.status}`
            );
        }

        alert(`Incident status updated to ${status}.`);

        await loadSecurityIncidents();

    }

    catch (error) {

        console.error(
            "INCIDENT STATUS UPDATE ERROR:",
            error
        );

        alert(
            `Unable to update incident status: ${error.message}`
        );

    }

    finally {

        if (button) {
            button.disabled = false;
            button.textContent = "Update";
        }

    }

}

// ============================================================
// SECURITY INCIDENTS
// ============================================================

async function loadSecurityIncidents() {

    try {

        const response = await apiFetch(
            `${API}/security/incidents`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );


        // ----------------------------------------------------
        // CHECK HTTP RESPONSE
        // ----------------------------------------------------

        if (!response.ok) {

            throw new Error(
                `Security incidents HTTP ${response.status}`
            );

        }


        // ----------------------------------------------------
        // READ INCIDENT DATA
        // ----------------------------------------------------

        const incidents =
            await response.json();


        // ----------------------------------------------------
        // FIND INCIDENT TABLE
        // ----------------------------------------------------

        const table =
            document.getElementById(
                "securityIncidentsTable"
            );


        if (!table) {

            console.error(
                "securityIncidentsTable not found"
            );

            return;

        }


        // Clear old data

        table.innerHTML = "";


        // ----------------------------------------------------
        // NO INCIDENTS
        // ----------------------------------------------------

        if (
            !Array.isArray(incidents) ||
            incidents.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td colspan="14">
                        No security incidents detected
                    </td>
                </tr>
            `;

            return;

        }


        // ----------------------------------------------------
        // PROCESS EACH INCIDENT
        // ----------------------------------------------------

        incidents.forEach(
            incident => {


                // =================================================
                // ATTACK RATE
                // =================================================

                let attackRate = 0;


                if (
                    incident.attack_rate !== undefined &&
                    incident.attack_rate !== null
                ) {

                    attackRate =
                        Number(
                            incident.attack_rate
                        ).toFixed(2);

                }

                else if (
                    incident.duration_seconds !== undefined &&
                    incident.duration_seconds > 0
                ) {

                    attackRate =
                        (
                            incident.total_attempts /
                            (
                                incident.duration_seconds /
                                60
                            )
                        ).toFixed(2);

                }

                else {

                    attackRate =
                        incident.total_attempts || 0;

                }


                // =================================================
                // FAILURE RATE
                // =================================================

                let failureRate = 0;


                if (
                    incident.failure_rate !== undefined &&
                    incident.failure_rate !== null
                ) {

                    failureRate =
                        Number(
                            incident.failure_rate
                        ).toFixed(2);

                }

                else if (
                    incident.total_attempts > 0
                ) {

                    failureRate =
                        (
                            (
                                incident.failed_logins /
                                incident.total_attempts
                            ) * 100
                        ).toFixed(2);

                }


                // =================================================
                // AI INCIDENT CONFIDENCE
                // =================================================
                //
                // IMPORTANT:
                //
                // The confidence is NOT calculated here.
                //
                // It comes directly from:
                //
                // backend/ai/incident_confidence.py
                //
                // Backend API:
                //
                // /security/incidents
                //
                // Fields:
                //
                // confidence_score
                // confidence_level
                // confidence_reasons
                //
                // =================================================


                const confidenceScore =
                    incident.confidence_score !== undefined
                        ? incident.confidence_score
                        : 0;


                const confidenceLevel =
                    incident.confidence_level ||
                    "UNKNOWN";


                const confidenceReasons =
                    Array.isArray(
                        incident.confidence_reasons
                    )
                        ? incident.confidence_reasons.join(
                            ", "
                        )
                        : "-";


                // =================================================
                // INCIDENT SEVERITY
                // =================================================

                const severity =
                    incident.severity ||
                    "UNKNOWN";


                // =================================================
                // INCIDENT TYPE
                // =================================================

                const incidentType =
                    incident.incident_type ||
                    incident.attack_pattern ||
                    "-";


                // =================================================
                // USERNAME
                // =================================================

                const username =
                    incident.username ||
                    "-";


                // =================================================
                // SOURCE IP
                // =================================================

                const sourceIP =
                    incident.source_ip ||
                    "-";


                // =================================================
                // CREATE TABLE ROW
                // =================================================

                const row =
                    document.createElement("tr");


                row.innerHTML = `

                    <td>
                        <strong>
                            ${severity}
                        </strong>
                    </td>


                    <td>
                        ${incidentType}
                    </td>


                    <td>
                        ${username}
                    </td>


                    <td>
                        ${sourceIP}
                    </td>


                    <td>
                        ${incident.total_attempts ?? 0}
                    </td>


                    <td>
                        ${incident.failed_logins ?? 0}
                    </td>


                    <td>
                        ${incident.invalid_users ?? 0}
                    </td>


                    <td>
                        ${attackRate}
                    </td>


                    <td>
                        ${failureRate}%
                    </td>


                    <td>

                        <strong>
                            ${confidenceScore}%
                        </strong>

                        <br>

                        <span>
                            ${confidenceLevel}
                        </span>

                        <br>

                        <small>
                            ${confidenceReasons}
                        </small>

                    </td>


                    <td>
                        ${
                            incident.start_time
                                ? new Date(
                                    incident.start_time
                                  ).toLocaleString()
                                : "-"
                        }
                    </td>


                    <td>
                        ${
                            incident.end_time
                                ? new Date(
                                    incident.end_time
                                  ).toLocaleString()
                                : "-"
                        }
                    </td>

                    <td>
                        ${incident.lifecycle_status || "OPEN"}
                    </td>

                    <td></td>
                `;


                // Add row to table

                // =====================================================
// ADMIN INCIDENT LIFECYCLE CONTROLS
// =====================================================

const actionCell = row.lastElementChild;

const incidentStatus = String(
    incident.lifecycle_status || "OPEN"
).toUpperCase();

if (currentUserRole === "admin") {

    const nextStatuses =
        getNextIncidentStatuses(incidentStatus);

    if (nextStatuses.length > 0 && incident.incident_id) {

        const statusSelect =
            document.createElement("select");

        statusSelect.style.marginRight = "8px";

        statusSelect.setAttribute(
            "aria-label",
            "Next incident lifecycle status"
        );

        nextStatuses.forEach((status) => {

            const option =
                document.createElement("option");

            option.value = status;
            option.textContent = status;

            statusSelect.appendChild(option);

        });

        const updateButton =
            document.createElement("button");

        updateButton.textContent = "Update";

        updateButton.addEventListener("click", () => {

            updateIncidentLifecycle(
                incident.incident_id,
                statusSelect.value,
                updateButton
            );

        });

        actionCell.appendChild(statusSelect);
        actionCell.appendChild(updateButton);

    } else {

        actionCell.textContent =
            incident.incident_id
                ? "No further transitions"
                : "Incident ID unavailable";

    }

} else {

    actionCell.textContent = "Read only";

}


// Add row to table

table.appendChild(row);

            }
        );


    }

    catch (error) {


        // =====================================================
        // ERROR HANDLING
        // =====================================================

        console.error(
            "SECURITY INCIDENT ERROR:",
            error
        );


        const table =
            document.getElementById(
                "securityIncidentsTable"
            );


        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="14">
                        Unable to load security incident data
                    </td>
                </tr>
            `;

        }

    }

}


// ============================================================
// CORRELATED ATTACK CAMPAIGNS
// ============================================================

async function loadSecurityCampaigns() {

    try {

        const response =
            await apiFetch(
                `${API}/security/campaigns`,
                {
                    method: "GET",
                    mode: "cors",
                    cache: "no-store"
                }
            );

        if (!response.ok) {

            throw new Error(
                `Security campaigns HTTP ${response.status}`
            );

        }

        const campaigns =
            await response.json();

        const table =
            document.getElementById(
                "securityCampaignsTable"
            );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (
            !Array.isArray(campaigns) ||
            campaigns.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td colspan="10">
                        No correlated attack campaigns detected
                    </td>
                </tr>
            `;

            return;
        }

        campaigns.forEach(campaign => {

            const row =
                document.createElement("tr");

            row.innerHTML = `

                <td>
                    <strong>
                        ${campaign.correlation_id || "-"}
                    </strong>
                </td>

                <td>
                    ${campaign.source_ip || "-"}
                </td>

                <td>
                    ${campaign.target_hostname || "-"}
                </td>

                <td>
                   ${campaign.target_ip || "-"}
                </td>

                <td>
                    ${campaign.attack_pattern || "-"}
                </td>

                <td>
                    <strong>
                        ${campaign.severity || "UNKNOWN"}
                    </strong>
                </td>

                <td>
                    ${campaign.incident_count ?? 0}
                </td>

                <td>
                    ${campaign.total_attempts ?? 0}
                </td>

                <td>
                    ${campaign.failed_logins ?? 0}
                </td>

                <td>
                    ${campaign.invalid_users ?? 0}
                </td>

                <td>
                    ${
                        campaign.start_time
                            ? new Date(
                                campaign.start_time
                              ).toLocaleString()
                            : "-"
                    }
                </td>

                <td>
                    ${
                        campaign.end_time
                            ? new Date(
                                campaign.end_time
                              ).toLocaleString()
                            : "-"
                    }
                </td>

            `;

            table.appendChild(row);

        });

    }

    catch (error) {

        console.error(
            "SECURITY CAMPAIGN ERROR:",
            error
        );

        const table =
            document.getElementById(
                "securityCampaignsTable"
            );

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="10">
                        Unable to load correlated attack campaigns
                    </td>
                </tr>
            `;

        }

    }

}


// ============================================================
// SECURITY RESPONSE RECOMMENDATIONS
// ============================================================

async function loadSecurityResponses() {

    try {

        const response =
            await apiFetch(
                `${API}/security/incidents`,
                {
                    method: "GET",
                    mode: "cors",
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `Security response HTTP ${response.status}`
            );
        }


        const incidents =
            await response.json();


        const table =
            document.getElementById(
                "securityResponses"
            );


        if (!table) {
            return;
        }


        table.innerHTML = "";


        if (incidents.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="6">
                        No security response recommendations
                    </td>
                </tr>
            `;

            return;
        }


        incidents.forEach(incident => {

            const row =
                document.createElement("tr");


            row.innerHTML = `
                <td>
                    ${incident.severity}
                </td>

                <td>
                    ${incident.incident_type}
                </td>

                <td>
                    ${incident.source_ip}
                </td>

                <td>
                    ${incident.recommended_action || "-"}
                </td>

                <td>
                    ${incident.response_description || "-"}
                </td>

                <td>
                    ${incident.response_mode || "-"}
                </td>
            `;


            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "SECURITY RESPONSE ERROR:",
            error
        );
    }
}


// ============================================================
// SECURITY RESPONSE EXECUTION
// ============================================================

async function loadResponseExecution() {

    try {

        const response =
            await apiFetch(
                `${API}/security/responses`,
                {
                    method: "GET",
                    mode: "cors",
                    cache: "no-store"
                }
            );

        if (!response.ok) {

            throw new Error(
                `Response execution HTTP ${response.status}`
            );
        }

        const responses =
            await response.json();

        const table =
            document.getElementById(
                "responseExecution"
            );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (
            !Array.isArray(responses) ||
            responses.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td colspan="9">
                        No AI response actions available
                    </td>
                </tr>
            `;

            return;
        }

        responses.forEach(responseData => {

            const row =
                document.createElement("tr");

            const severity =
                responseData.severity || "-";

            const sourceIP =
                responseData.source_ip || "-";

            const threatScore =
                responseData.threat_score ?? "-";

            const priority =
                responseData.priority || "-";

            const aiDecision =
                responseData.ai_decision ||
                responseData.recommended_action ||
                "-";

            const confidenceScore =
                responseData.confidence_score ?? "-";

            const confidenceLevel =
                responseData.confidence_level || "-";

            const executionMode =
                responseData.execution_mode || "-";

            const executed =
                responseData.executed ? "YES" : "NO";

            const executionMessage =
                responseData.execution_message || "-";

            row.innerHTML = `

                <td>
                    <strong>
                        ${severity}
                    </strong>
                </td>

                <td>
                    ${sourceIP}
                </td>

                <td>
                    <strong>
                        ${threatScore}/100
                    </strong>
                </td>

                <td>
                    <strong>
                        ${priority}
                    </strong>
                </td>

                <td>
                    <strong>
                        ${aiDecision}
                    </strong>
                </td>

                <td>
                    <strong>
                        ${confidenceScore}%
                    </strong>
                    <br>
                    <small>
                        ${confidenceLevel}
                    </small>
                </td>

                <td>
                    ${executionMode}
                </td>

                <td>
                    <strong>
                        ${executed}
                    </strong>
                </td>

                <td>
                    ${executionMessage}
                </td>

            `;

            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "RESPONSE EXECUTION ERROR:",
            error
        );

        const table =
            document.getElementById(
                "responseExecution"
            );

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="9">
                        Unable to load AI response execution data
                    </td>
                </tr>
            `;

        }

    }

}

// ============================================================
// AI SECURITY INTELLIGENCE
// ============================================================

async function loadSecurityDecisions() {

    try {

        const response =
            await apiFetch(
                `${API}/security/decisions`,
                {
                    method: "GET",
                    mode: "cors",
                    cache: "no-store"
                }
            );

        if (!response.ok) {

            throw new Error(
                `Security decisions HTTP ${response.status}`
            );
        }

        const decisions =
            await response.json();

        const table =
            document.getElementById(
                "securityDecisionsTable"
            );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (
            !Array.isArray(decisions) ||
            decisions.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td colspan="8">
                        No AI security decisions available
                    </td>
                </tr>
            `;

            return;
        }

        decisions.forEach(decision => {

            const row =
                document.createElement("tr");

            const severity =
                decision.severity || "-";

            const sourceIP =
                decision.source_ip || "-";

            const threatScore =
                decision.threat_score ?? "-";

            const priority =
                decision.priority || "-";

            const confidenceScore =
                decision.confidence_score ?? "-";

            const confidenceLevel =
                decision.confidence_level || "-";

            const securityDecision =
                decision.decision ||
                decision.recommended_action ||
                "-";

            const explanation =
                decision.explanation || "-";

            const executionMode =
                decision.execution_mode || "-";

            row.innerHTML = `

                <td>
                    <strong>
                        ${severity}
                    </strong>
                </td>

                <td>
                    ${sourceIP}
                </td>

                <td>
                    <strong>
                        ${threatScore}/100
                    </strong>
                </td>

                <td>
                    <strong>
                        ${priority}
                    </strong>
                </td>

                <td>
                    <strong>
                        ${confidenceScore}%
                    </strong>
                    <br>
                    <small>
                        ${confidenceLevel}
                    </small>
                </td>

                <td>
                    <strong>
                        ${securityDecision}
                    </strong>
                </td>

                <td>
                    ${explanation}
                </td>

                <td>
                    ${executionMode}
                </td>

            `;

            table.appendChild(row);

        });

    }

    catch (error) {

        console.error(
            "AI SECURITY DECISION ERROR:",
            error
        );

        const table =
            document.getElementById(
                "securityDecisionsTable"
            );

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="8">
                        Unable to load AI security decisions
                    </td>
                </tr>
            `;

        }

    }

}

// ============================================================
// SECURITY RESPONSE AUDIT HISTORY
// ============================================================

async function loadSecurityResponseAudit() {

    try {

        const response = await apiFetch(
            `${API}/security/response-audit?limit=20`
        );

        const audits = await response.json();

        const table =
            document.getElementById(
                "responseAuditTable"
            );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (!audits || audits.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="10">
                        No security response audit records found
                    </td>
                </tr>
            `;

            return;

        }

        audits.forEach(audit => {

            const row =
                document.createElement("tr");

            const createdAt =
                audit.created_at
                    ? new Date(
                        audit.created_at
                    ).toLocaleString()
                    : "-";

            const executed =
                audit.executed
                    ? "YES"
                    : "NO";

            row.innerHTML = `

                <td>
                    ${createdAt}
                </td>

                <td>
                    ${audit.incident_id || "-"}
                </td>

                <td>
                    <strong>
                        ${audit.severity || "-"}
                    </strong>
                </td>

                <td>
                    ${audit.source_ip || "-"}
                </td>

                <td>
                    <strong>
                        ${audit.threat_score ?? 0}/100
                    </strong>
                </td>

                <td>
                    <strong>
                        ${audit.priority || "-"}
                    </strong>
                </td>

                <td>
                    <strong>
                        ${audit.ai_decision || "-"}
                    </strong>
                </td>

                <td>
                    ${audit.execution_action || "-"}
                </td>

                <td>
                    ${audit.execution_mode || "-"}
                </td>

                <td>
                    ${executed}
                </td>

            `;

            table.appendChild(row);

        });

    }

    catch (error) {

        console.error(
            "SECURITY RESPONSE AUDIT ERROR:",
            error
        );

        const table =
            document.getElementById(
                "responseAuditTable"
            );

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="10">
                        Unable to load security response audit history
                    </td>
                </tr>
            `;

        }

    }

}

// ============================================================
// INITIAL LOAD
// ============================================================

// ============================================================
// AUTHENTICATED DASHBOARD INITIALIZATION
// ============================================================

console.log(
    "=== AUTHENTICATED DASHBOARD READY ==="
);



// ============================================================
// PHASE 21.6 FEATURE 7 - ADMIN NOTIFICATION SETTINGS
// ============================================================

function setNotificationSettingsMessage(message) {

    const element = document.getElementById(
        "notificationSettingsMessage"
    );

    if (element) {
        element.textContent = message;
    }

}


// ------------------------------------------------------------
// LOAD AND DISPLAY NOTIFICATION SETTINGS
// ------------------------------------------------------------

async function loadNotificationSettings() {

    const table = document.getElementById(
        "notificationSettingsTable"
    );

    if (!table) {
        return;
    }

    try {

        const response = await apiFetch(
            `${API}/security/notification-settings`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const settings = await response.json();

        table.textContent = "";

        const isAdmin =
            currentUserRole === "admin";

        const channels = [
            {
                name: "EMAIL",
                field: "email_enabled"
            },
            {
                name: "TELEGRAM",
                field: "telegram_enabled"
            },
            {
                name: "DASHBOARD",
                field: "dashboard_enabled"
            }
        ];

        settings.forEach(setting => {

            const row = document.createElement("tr");

            const severityCell = document.createElement("td");
            severityCell.textContent = setting.severity;
            row.appendChild(severityCell);

            const priorityCell = document.createElement("td");
            priorityCell.textContent = setting.priority || "-";
            row.appendChild(priorityCell);

            channels.forEach(channel => {

                const cell = document.createElement("td");

                const enabled = Boolean(
                    setting[channel.field]
                );

                const isCriticalDashboard =
                    setting.severity === "CRITICAL" &&
                    channel.name === "DASHBOARD";

                if (isAdmin) {

                    const button =
                        document.createElement("button");

                    button.type = "button";

                    button.className =
                        "notification-setting-button";

                    button.textContent = enabled
                        ? "ENABLED"
                        : "DISABLED";

                    button.classList.add(
                        enabled ? "setting-enabled" : "setting-disabled"
                    );

                    button.disabled = isCriticalDashboard;

                    if (isCriticalDashboard) {

                        button.title =
                            "Critical dashboard notifications cannot be disabled.";

                    } else {

                        button.addEventListener(
                            "click",
                            () => updateNotificationSetting(
                                setting.severity,
                                channel.name,
                                !enabled
                            )
                        );

                    }

                    cell.appendChild(button);

                } else {

                    cell.textContent = enabled
                        ? "ENABLED"
                        : "DISABLED";

                }

                row.appendChild(cell);

            });

            table.appendChild(row);

        });

        setNotificationSettingsMessage(
            isAdmin
                ? "Admin mode: You can update notification policies."
                : "Read-only mode: Only administrators can change notification policies."
        );

    } catch (error) {

        console.error(
            "NOTIFICATION SETTINGS LOAD ERROR:",
            error
        );

        table.textContent = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.textContent =
            "Unable to load notification settings.";

        row.appendChild(cell);
        table.appendChild(row);

        setNotificationSettingsMessage(
            "Error loading notification settings."
        );

    }

}


// ------------------------------------------------------------
// UPDATE A NOTIFICATION POLICY
// ------------------------------------------------------------

async function updateNotificationSetting(
    severity,
    channel,
    enabled
) {

    if (currentUserRole !== "admin") {

        setNotificationSettingsMessage(
            "Permission denied: Admin access required."
        );

        return;

    }

    if (
        severity === "CRITICAL" &&
        channel === "DASHBOARD" &&
        !enabled
    ) {

        setNotificationSettingsMessage(
            "Critical dashboard notifications cannot be disabled."
        );

        return;

    }

    const action = enabled
        ? "enable"
        : "disable";

    const confirmed = window.confirm(
        `Are you sure you want to ${action} ${channel} notifications for ${severity} incidents?`
    );

    if (!confirmed) {
        return;
    }

    try {

        setNotificationSettingsMessage(
            `Updating ${severity} ${channel} policy...`
        );

        const response = await apiFetch(
            `${API}/security/notification-settings/${severity}/${channel}`,
            {
                method: "PUT",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    enabled: enabled
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.detail || `HTTP ${response.status}`
            );

        }

        setNotificationSettingsMessage(
            data.status === "unchanged"
                ? "The notification policy was already set to that value."
                : `${severity} ${channel} notifications successfully ${action}d.`
        );

        await loadNotificationSettings();
        await loadNotificationSettingsAudit();

    } catch (error) {

        console.error(
            "NOTIFICATION SETTINGS UPDATE ERROR:",
            error
        );

        setNotificationSettingsMessage(
            `Update failed: ${error.message}`
        );

    }

}


// ------------------------------------------------------------
// LOAD NOTIFICATION SETTINGS AUDIT HISTORY
// ------------------------------------------------------------

async function loadNotificationSettingsAudit() {

    const table = document.getElementById(
        "notificationSettingsAuditTable"
    );

    if (!table) {
        return;
    }

    try {

        const response = await apiFetch(
            `${API}/security/notification-settings/audit?limit=100`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const records = await response.json();

        table.textContent = "";

        if (!records.length) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 7;
            cell.textContent = "No settings changes recorded.";

            row.appendChild(cell);
            table.appendChild(row);

            return;

        }

        records.forEach(record => {

            const row = document.createElement("tr");

            const values = [
                record.id,
                record.severity,
                record.channel,
                record.old_enabled ? "ENABLED" : "DISABLED",
                record.new_enabled ? "ENABLED" : "DISABLED",
                record.changed_by_username,
                record.changed_at
                    ? new Date(record.changed_at).toLocaleString()
                    : "-"
            ];

            values.forEach(value => {

                const cell = document.createElement("td");

                cell.textContent =
                    value === null || value === undefined
                        ? "-"
                        : String(value);

                row.appendChild(cell);

            });

            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "NOTIFICATION SETTINGS AUDIT ERROR:",
            error
        );

        table.textContent = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 7;
        cell.textContent =
            "Unable to load notification settings audit history.";

        row.appendChild(cell);
        table.appendChild(row);

    }

}


// ============================================================
// NOTIFICATION DELIVERY HEALTH MONITOR
// ============================================================

async function loadDeliveryHealth() {

    try {

        const response = await apiFetch(
            `${API}/security/delivery-health`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        const summary = data.summary || {};

        function updateText(id, value) {

            const element = document.getElementById(id);

            if (element) {
                element.textContent = value;
            }
        }

        updateText(
            "deliveryOverallHealth",
            data.overall_health || "UNKNOWN"
        );

        updateText(
            "deliveryTotalAttempts",
            summary.total_attempts ?? 0
        );

        updateText(
            "deliverySent",
            summary.sent ?? 0
        );

        updateText(
            "deliveryFailed",
            summary.failed ?? 0
        );

        updateText(
            "deliveryPending",
            summary.pending ?? 0
        );

        updateText(
            "deliveryOverdue",
            summary.overdue ?? 0
        );

        updateText(
            "deliverySuccessRate",
            summary.success_rate === null
                ? "N/A"
                : `${summary.success_rate}%`
        );

        updateText(
            "deliveryFailureRate",
            summary.failure_rate === null
                ? "N/A"
                : `${summary.failure_rate}%`
        );

        // ----------------------------------------------------
        // CHANNEL HEALTH TABLE
        // ----------------------------------------------------

        const table = document.getElementById(
            "deliveryChannelTable"
        );

        if (table) {

            table.innerHTML = "";

            const channels = data.channels || {};

            Object.entries(channels).forEach(
                ([name, channel]) => {

                    const row = document.createElement("tr");

                    const values = [
                        name.toUpperCase(),
                        channel.health,
                        channel.total,
                        channel.sent,
                        channel.failed,
                        channel.pending,
                        channel.total_attempts,
                        channel.success_rate === null
                            ? "N/A"
                            : `${channel.success_rate}%`
                    ];

                    values.forEach(value => {

                        const cell =
                            document.createElement("td");

                        cell.textContent =
                            value === null || value === undefined
                                ? "-"
                                : String(value);

                        row.appendChild(cell);

                    });

                    table.appendChild(row);

                }
            );

        }

        updateText(
            "deliveryHealthUpdated",
            `Last updated: ${new Date().toLocaleString()}`
        );

    } catch (error) {

        console.error(
            "DELIVERY HEALTH ERROR:",
            error
        );

        updateText(
            "deliveryOverallHealth",
            "Unavailable"
        );

        updateText(
            "deliveryHealthUpdated",
            "Unable to retrieve delivery health."
        );

    }

}


// ============================================================
// NOTIFICATION ANALYTICS AND REPORTING
// ============================================================

async function loadNotificationAnalytics() {

    const updateText = (id, value) => {

        const element = document.getElementById(id);

        if (element) {
            element.textContent = value;
        }

    };

    try {

        const period =
            document.getElementById("analyticsPeriod")?.value
            || "daily";

        const days =
            document.getElementById("analyticsDays")?.value
            || "90";

        updateText("analyticsUpdated", "Loading analytics...");

        const response = await apiFetch(
            `${API}/security/notification-analytics?days=${encodeURIComponent(days)}&period=${encodeURIComponent(period)}`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        const events = data.event_notifications || {};
        const incidents = data.incident_deliveries || {};

        const eventSummary = events.summary || {};
        const incidentSummary = incidents.summary || {};

        // ----------------------------------------------------
        // SUMMARY CARDS
        // ----------------------------------------------------

        updateText(
            "analyticsEventTotal",
            eventSummary.total_recorded_successes ?? 0
        );

        updateText(
            "analyticsIncidentTotal",
            incidentSummary.total_records ?? 0
        );

        updateText(
            "analyticsIncidentSent",
            incidentSummary.sent ?? 0
        );

        updateText(
            "analyticsIncidentFailed",
            incidentSummary.failed ?? 0
        );

        updateText(
            "analyticsIncidentPending",
            incidentSummary.pending ?? 0
        );

        updateText(
            "analyticsIncidentAttempts",
            incidentSummary.total_attempts ?? 0
        );

        // ----------------------------------------------------
        // DESTROY PREVIOUS CHARTS
        // ----------------------------------------------------

        [
            notificationEventTrendChart,
            notificationChannelChart,
            notificationSeverityChart,
            incidentDeliveryChart,
            incidentRetryChart
        ].forEach(chart => {

            if (chart) {
                chart.destroy();
            }

        });

        if (typeof Chart === "undefined") {
            updateText(
                "analyticsUpdated",
                `Last updated: ${new Date().toLocaleString()} | ${period.toUpperCase()} | Last ${days} days (Charts unavailable offline)`
            );
            return;
        }

        // ----------------------------------------------------
        // EVENT NOTIFICATION TREND
        // ----------------------------------------------------

        const eventTrend = events.trend || [];

        const eventPeriods = [
            ...new Set(
                eventTrend.map(item => item.period_start)
            )
        ].sort();

        const eventChannels = [
            ...new Set(
                eventTrend.map(item => item.notification_channel)
            )
        ];

        const eventDatasets = eventChannels.map(channel => ({

            label: channel.toUpperCase(),

            data: eventPeriods.map(periodStart => {

                const record = eventTrend.find(
                    item =>
                        item.period_start === periodStart &&
                        item.notification_channel === channel
                );

                return record?.recorded_successes ?? 0;

            }),

            tension: 0.3

        }));

        notificationEventTrendChart = new Chart(
            document.getElementById("notificationEventTrendChart"),
            {
                type: "line",

                data: {
                    labels: eventPeriods.map(
                        value => new Date(value).toLocaleDateString()
                    ),
                    datasets: eventDatasets
                },

                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );

        // ----------------------------------------------------
        // EVENT CHANNEL COMPARISON
        // ----------------------------------------------------

        const channelRecords = events.by_channel || [];

        notificationChannelChart = new Chart(
            document.getElementById("notificationChannelChart"),
            {
                type: "bar",

                data: {
                    labels: channelRecords.map(
                        item => item.notification_channel.toUpperCase()
                    ),

                    datasets: [{
                        label: "Recorded Successful Event Notifications",

                        data: channelRecords.map(
                            item => item.recorded_successes
                        )
                    }]
                },

                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );

        // ----------------------------------------------------
        // EVENT SEVERITY DISTRIBUTION
        // ----------------------------------------------------

        const severityRecords = events.by_severity || [];

        notificationSeverityChart = new Chart(
            document.getElementById("notificationSeverityChart"),
            {
                type: "doughnut",

                data: {
                    labels: severityRecords.map(
                        item => item.alert_level
                    ),

                    datasets: [{
                        label: "Event Notification Successes",

                        data: severityRecords.map(
                            item => item.recorded_successes
                        )
                    }]
                },

                options: {
                    responsive: true
                }
            }
        );

        // ----------------------------------------------------
        // INCIDENT DELIVERY STATUS
        // ----------------------------------------------------

        incidentDeliveryChart = new Chart(
            document.getElementById("incidentDeliveryChart"),
            {
                type: "bar",

                data: {
                    labels: ["Sent", "Failed", "Pending"],

                    datasets: [{
                        label: "Incident Delivery Records",

                        data: [
                            incidentSummary.sent ?? 0,
                            incidentSummary.failed ?? 0,
                            incidentSummary.pending ?? 0
                        ]
                    }]
                },

                options: {
                    responsive: true,

                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );

        // ----------------------------------------------------
        // INCIDENT RETRY ATTEMPTS BY CHANNEL
        // ----------------------------------------------------

        const incidentChannels =
            incidents.by_channel || [];

        incidentRetryChart = new Chart(
            document.getElementById("incidentRetryChart"),
            {
                type: "bar",

                data: {
                    labels: incidentChannels.map(
                        item => item.notification_channel.toUpperCase()
                    ),

                    datasets: [{
                        label: "Total Delivery Attempts",

                        data: incidentChannels.map(
                            item => item.total_attempts
                        )
                    }]
                },

                options: {
                    responsive: true,

                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );

        updateText(
            "analyticsUpdated",
            `Last updated: ${new Date().toLocaleString()} | ${period.toUpperCase()} | Last ${days} days`
        );

    } catch (error) {

        console.error(
            "NOTIFICATION ANALYTICS ERROR:",
            error
        );

        updateText(
            "analyticsUpdated",
            "Unable to retrieve notification analytics."
        );

    }

}


// ============================================================
// PHASE 21.6 FEATURE 8 - NOTIFICATION POLICY SIMULATOR
// ============================================================


// RUN NOTIFICATION POLICY SIMULATION

async function runNotificationSimulation() {

    const severity =
        document.getElementById(
            "simulationSeverity"
        )?.value;

    const message =
        document.getElementById(
            "notificationSimulationMessage"
        );

    const resultsTable =
        document.getElementById(
            "notificationSimulationResults"
        );

    if (!severity || !message || !resultsTable) {
        return;
    }

    message.textContent = "Running simulation...";

    resultsTable.textContent = "";

    try {

        const response = await apiFetch(
            `${API}/security/notification-simulator`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    severity: severity
                })
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const result = await response.json();

        message.textContent =
            `Simulation #${result.simulation_id} completed. ` +
            "DRY-RUN — NO NOTIFICATIONS SENT.";

        const channels = [
            {
                name: "Email",
                key: "email"
            },
            {
                name: "Telegram",
                key: "telegram"
            },
            {
                name: "Dashboard",
                key: "dashboard"
            }
        ];

        channels.forEach(channel => {

            const decision =
                result.channels[channel.key];

            const row = document.createElement("tr");

            const nameCell =
                document.createElement("td");

            nameCell.textContent = channel.name;

            const statusCell =
                document.createElement("td");

            statusCell.textContent =
                decision.allowed
                    ? "ALLOWED — NOT SENT"
                    : "BLOCKED BY POLICY";

            const reasonCell =
                document.createElement("td");

            reasonCell.textContent =
                decision.reason;

            row.appendChild(nameCell);
            row.appendChild(statusCell);
            row.appendChild(reasonCell);

            resultsTable.appendChild(row);

        });

        await loadNotificationSimulationHistory();

    } catch (error) {

        console.error(
            "NOTIFICATION SIMULATION ERROR:",
            error
        );

        message.textContent =
            "Unable to run notification simulation.";

        resultsTable.textContent = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 3;
        cell.textContent = "Simulation failed.";

        row.appendChild(cell);
        resultsTable.appendChild(row);

    }

}


// LOAD NOTIFICATION SIMULATION HISTORY

async function loadNotificationSimulationHistory() {

    const table =
        document.getElementById(
            "notificationSimulationHistoryTable"
        );

    if (!table) {
        return;
    }

    try {

        const response = await apiFetch(
            `${API}/security/notification-simulator/history?limit=50`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const records = await response.json();

        table.textContent = "";

        if (!records.length) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 9;

            cell.textContent =
                "No simulation history available.";

            row.appendChild(cell);
            table.appendChild(row);

            return;

        }

        records.forEach(record => {

            const row = document.createElement("tr");

            const values = [
                record.id,
                record.severity,
                record.priority,
                record.email_allowed ? "ALLOWED" : "BLOCKED",
                record.telegram_allowed ? "ALLOWED" : "BLOCKED",
                record.dashboard_allowed ? "ALLOWED" : "BLOCKED",
                record.simulation_mode,
                record.simulated_by_username,
                record.created_at
                    ? new Date(record.created_at).toLocaleString()
                    : "-"
            ];

            values.forEach(value => {

                const cell = document.createElement("td");

                cell.textContent =
                    value === null || value === undefined
                        ? "-"
                        : String(value);

                row.appendChild(cell);

            });

            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "NOTIFICATION SIMULATION HISTORY ERROR:",
            error
        );

        table.textContent = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 9;

        cell.textContent =
            "Unable to load simulation history.";

        row.appendChild(cell);
        table.appendChild(row);

    }

}

// ============================================================
// PHASE 22: AI THREAT INTELLIGENCE & IOC DASHBOARD INTEGRATION
// ============================================================

async function loadThreatIntelligence() {
    try {
        // 1. Load Threat Stats
        const statsRes = await apiFetch("/threat-intel/stats");
        if (statsRes && statsRes.ok) {
            const stats = await statsRes.json();
            const totalEl = document.getElementById("threatTotalIocs");
            const critEl = document.getElementById("threatCriticalIocs");
            const lookupEl = document.getElementById("threatLookupCount");
            const mitreEl = document.getElementById("threatMitreCount");
            if (totalEl) totalEl.textContent = stats.total_active_iocs ?? 0;
            if (critEl) critEl.textContent = stats.critical_severity_count ?? 0;
            if (lookupEl) lookupEl.textContent = stats.total_lookups ?? 0;
            if (mitreEl) mitreEl.textContent = stats.mitre_techniques_cataloged ?? 0;
        }

        // 2. Load Indicators Table
        const indicatorsRes = await apiFetch("/threat-intel/indicators?limit=25");
        const tbody = document.getElementById("threatIndicatorsTable");
        if (!tbody) return;

        if (indicatorsRes && indicatorsRes.ok) {
            const indicators = await indicatorsRes.json();
            tbody.textContent = "";

            if (!indicators || indicators.length === 0) {
                const tr = document.createElement("tr");
                const td = document.createElement("td");
                td.colSpan = 8;
                td.textContent = "No active threat indicators currently recorded.";
                tr.appendChild(td);
                tbody.appendChild(tr);
                return;
            }

            indicators.forEach(ioc => {
                const tr = document.createElement("tr");

                const sevColor = ioc.severity === "CRITICAL" ? "#dc2626" :
                                 ioc.severity === "HIGH" ? "#ea580c" :
                                 ioc.severity === "MEDIUM" ? "#d97706" : "#16a34a";

                tr.innerHTML = `
                    <td style="font-family: monospace; font-weight: bold;">${escapeHtml(ioc.indicator_value)}</td>
                    <td><span style="background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: 11px;">${escapeHtml(ioc.indicator_type || "IP")}</span></td>
                    <td>${escapeHtml(ioc.threat_type || "-")}</td>
                    <td><span style="color: white; background: ${sevColor}; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">${escapeHtml(ioc.severity || "MEDIUM")}</span></td>
                    <td>${ioc.confidence_score ?? 70}%</td>
                    <td><span style="color: #2563eb; font-weight: 500;">${escapeHtml(ioc.mitre_attack_id || "T1110")}</span> <small>(${escapeHtml(ioc.mitre_tactic || "")})</small></td>
                    <td>${escapeHtml(ioc.source_feed || "Intelligence")}</td>
                    <td><span style="font-size: 12px; font-weight: 600; color: ${ioc.severity === 'CRITICAL' ? '#dc2626' : '#2563eb'}">${ioc.severity === 'CRITICAL' ? 'BLOCK' : 'MONITOR'}</span></td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error("Error loading threat intelligence:", err);
    }
}

async function queryThreatLookup() {
    const input = document.getElementById("threatLookupInput");
    const resultBox = document.getElementById("threatLookupResult");
    if (!input || !resultBox) return;

    const val = input.value.trim();
    if (!val) {
        resultBox.style.display = "block";
        resultBox.style.background = "#fee2e2";
        resultBox.style.color = "#991b1b";
        resultBox.textContent = "Please enter an IP, domain, URL, or hash.";
        return;
    }

    resultBox.style.display = "block";
    resultBox.style.background = "#f1f5f9";
    resultBox.style.color = "#334155";
    resultBox.textContent = `Querying intelligence for "${val}"...`;

    try {
        const res = await apiFetch(`/threat-intel/lookup/${encodeURIComponent(val)}`);
        if (!res.ok) throw new Error(`Lookup failed: ${res.statusText}`);
        const data = await res.json();

        if (data.matched) {
            const sevColor = data.severity === "CRITICAL" ? "#ef4444" : "#f97316";
            resultBox.style.background = "#fef2f2";
            resultBox.style.color = "#991b1b";
            resultBox.style.border = "1px solid #fecaca";
            resultBox.innerHTML = `
                <div style="font-weight: bold; font-size: 15px; margin-bottom: 5px;">
                    ⚠️ MALICIOUS INDICATOR DETECTED
                </div>
                <div><strong>Indicator:</strong> <code>${escapeHtml(data.indicator_value)}</code> (${data.indicator_type})</div>
                <div><strong>Threat Type:</strong> ${escapeHtml(data.threat_type)} | <strong>Threat Score:</strong> ${data.threat_score}/100 (<span style="color: ${sevColor}; font-weight: bold;">${data.severity}</span>)</div>
                <div><strong>Confidence:</strong> ${data.confidence_score}% | <strong>Source Feed:</strong> ${escapeHtml(data.source_feed || "Unknown")}</div>
                ${data.mitre_attack ? `<div><strong>MITRE ATT&CK:</strong> ${escapeHtml(data.mitre_attack.attack_id)} - ${escapeHtml(data.mitre_attack.technique_name)} (${escapeHtml(data.mitre_attack.tactic)})</div>` : ''}
                <div style="margin-top: 5px;"><strong>Description:</strong> ${escapeHtml(data.description || "-")}</div>
                <div style="margin-top: 8px; font-weight: bold; color: #b91c1c;">Recommended Action: ${escapeHtml(data.recommendation)}</div>
            `;
        } else {
            resultBox.style.background = "#f0fdf4";
            resultBox.style.color = "#166534";
            resultBox.style.border = "1px solid #bbf7d0";
            resultBox.innerHTML = `
                <div style="font-weight: bold; font-size: 14px;">✅ No Malicious Activity Recorded</div>
                <div style="margin-top: 4px;">Indicator <code>${escapeHtml(data.indicator_value)}</code> is clean across active intelligence feeds.</div>
            `;
        }
        // Refresh lookup counter
        loadThreatIntelligence();
    } catch (err) {
        resultBox.style.background = "#fee2e2";
        resultBox.style.color = "#991b1b";
        resultBox.textContent = `Error performing lookup: ${err.message}`;
    }
}

async function loadMitreCoverage() {
    try {
        const res = await apiFetch("/threat-intel/mitre");
        const container = document.getElementById("mitreTechniquesList");
        if (!container || !res.ok) return;

        const techniques = await res.json();
        container.textContent = "";

        techniques.forEach(t => {
            const badge = document.createElement("div");
            badge.style.cssText = "padding: 8px 12px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); font-size: 12px;";
            badge.innerHTML = `
                <strong style="color: #0077cc;">${escapeHtml(t.id)}</strong> - <span>${escapeHtml(t.name)}</span>
                <div style="color: #64748b; font-size: 11px; margin-top: 2px;">Tactic: <em>${escapeHtml(t.tactic)}</em></div>
            `;
            container.appendChild(badge);
        });
    } catch (err) {
        console.error("Error loading MITRE coverage:", err);
    }
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ============================================================
// PHASE 23: PREDICTIVE RESOURCE ANALYTICS DASHBOARD
// ============================================================

let predictiveForecastChartInstance = null;

async function loadPredictiveAnalytics() {
    const activeHost = currentFleetHost || "localhost";
    try {
        const res = await apiFetch(`/predictive-analytics/forecast?hostname=${encodeURIComponent(activeHost)}`);
        if (!res || !res.ok) return;

        const data = await res.json();
        const cpu = data.cpu || {};
        const mem = data.memory || {};
        const disk = data.disk || {};
        const anomaly = data.anomaly_trend || {};
        const alerts = data.predictive_alerts || [];

        // 1. KPI Cards
        const cpuValEl = document.getElementById("predCpuVal");
        const cpuTrendEl = document.getElementById("predCpuTrend");
        if (cpuValEl) {
            cpuValEl.textContent = `${cpu.predicted_15m ?? 0}%`;
            const trendArrow = cpu.trend_direction === "RISING" ? "↑ Rising" :
                               cpu.trend_direction === "FALLING" ? "↓ Falling" : "→ Stable";
            const trendColor = cpu.trend_direction === "RISING" ? "#ea580c" : "#16a34a";
            cpuTrendEl.innerHTML = `<span style="color: ${trendColor}; font-weight: bold;">${trendArrow}</span> (${cpu.rate_per_hour >= 0 ? '+' : ''}${cpu.rate_per_hour}%/h)`;
        }

        const memValEl = document.getElementById("predMemVal");
        const memTrendEl = document.getElementById("predMemTrend");
        if (memValEl) {
            memValEl.textContent = `${mem.predicted_1h ?? 0}%`;
            memTrendEl.textContent = `Rate: ${mem.rate_per_hour >= 0 ? '+' : ''}${mem.rate_per_hour}%/h (Conf: ${mem.confidence_pct ?? 0}%)`;
        }

        const diskExEl = document.getElementById("predDiskExhaustion");
        const diskStatusEl = document.getElementById("predDiskStatus");
        if (diskExEl) {
            if (disk.time_to_exhaustion_hours) {
                diskExEl.textContent = `${disk.time_to_exhaustion_hours} hrs`;
                diskStatusEl.textContent = "Urgent: Nearing 95% threshold";
                diskStatusEl.style.color = "#dc2626";
            } else {
                diskExEl.textContent = "> 30 days";
                diskStatusEl.textContent = `Stable (+${disk.rate_per_hour}%/h)`;
                diskStatusEl.style.color = "#16a34a";
            }
        }

        const anomProbEl = document.getElementById("predAnomalyProb");
        const anomStatusEl = document.getElementById("predAnomalyStatus");
        if (anomProbEl) {
            anomProbEl.textContent = `${anomaly.probability_pct ?? 0}%`;
            const anomColor = anomaly.probability_pct >= 75 ? "#dc2626" :
                              anomaly.probability_pct >= 45 ? "#ea580c" : "#16a34a";
            anomProbEl.style.color = anomColor;
            anomStatusEl.textContent = anomaly.status || "NOMINAL";
        }

        // 2. Predictive Alerts Banner
        const alertsBanner = document.getElementById("predictiveAlertsBanner");
        if (alertsBanner) {
            if (alerts.length > 0) {
                alertsBanner.style.display = "block";
                alertsBanner.innerHTML = `
                    <div style="font-weight: bold; color: #b45309; margin-bottom: 5px;">⚡ Proactive Capacity & Performance Warnings (${alerts.length})</div>
                    ${alerts.map(a => `
                        <div style="margin-top: 4px; font-size: 13px; color: #78350f;">
                            <strong>[${escapeHtml(a.severity)}] ${escapeHtml(a.alert_type)}:</strong> ${escapeHtml(a.recommendation)} 
                            <small><em>(Horizon: ${a.time_horizon_minutes}m, Conf: ${a.confidence_pct}%)</em></small>
                        </div>
                    `).join('')}
                `;
            } else {
                alertsBanner.style.display = "none";
            }
        }

        // 3. Confidence Badge
        const confBadge = document.getElementById("forecastConfidenceBadge");
        if (confBadge && cpu.confidence_pct) {
            confBadge.textContent = `ML Confidence: ${cpu.confidence_pct}% (${cpu.model_type})`;
        }

        // 4. Render Forecast Chart
        renderPredictiveChart(cpu, mem);

    } catch (err) {
        console.error("Error loading predictive analytics:", err);
    }
}

function renderPredictiveChart(cpuForecast, memForecast) {
    const canvas = document.getElementById("predictiveForecastChart");
    if (!canvas || typeof Chart === "undefined") return;

    const ctx = canvas.getContext("2d");
    const labels = ["Now", "+5m", "+10m", "+15m", "+20m", "+25m", "+30m", "+35m", "+40m", "+45m", "+50m", "+55m", "+60m"];

    const cpuPoints = [cpuForecast.current_value, ...(cpuForecast.predictions_series || [])].slice(0, 13);
    const memPoints = [memForecast.current_value, ...(memForecast.predictions_series || [])].slice(0, 13);
    const cpuUpper = [cpuForecast.current_value, ...(cpuForecast.upper_bounds || [])].slice(0, 13);
    const cpuLower = [cpuForecast.current_value, ...(cpuForecast.lower_bounds || [])].slice(0, 13);

    if (predictiveForecastChartInstance) {
        predictiveForecastChartInstance.data.labels = labels;
        predictiveForecastChartInstance.data.datasets[0].data = cpuPoints;
        predictiveForecastChartInstance.data.datasets[1].data = memPoints;
        predictiveForecastChartInstance.data.datasets[2].data = cpuUpper;
        predictiveForecastChartInstance.data.datasets[3].data = cpuLower;
        predictiveForecastChartInstance.update();
        return;
    }

    predictiveForecastChartInstance = new Chart(ctx, {
        type: "line",
        data: {
            labels: labels,
            datasets: [
                {
                    label: "CPU Usage Projected (%)",
                    data: cpuPoints,
                    borderColor: "#ef4444",
                    backgroundColor: "rgba(239, 68, 68, 0.1)",
                    borderWidth: 2,
                    borderDash: [5, 5],
                    fill: false,
                    tension: 0.3
                },
                {
                    label: "Memory Usage Projected (%)",
                    data: memPoints,
                    borderColor: "#3b82f6",
                    backgroundColor: "rgba(59, 130, 246, 0.1)",
                    borderWidth: 2,
                    borderDash: [5, 5],
                    fill: false,
                    tension: 0.3
                },
                {
                    label: "CPU Upper Confidence Bound (95%)",
                    data: cpuUpper,
                    borderColor: "rgba(239, 68, 68, 0.25)",
                    borderWidth: 1,
                    pointRadius: 0,
                    fill: false
                },
                {
                    label: "CPU Lower Confidence Bound (95%)",
                    data: cpuLower,
                    borderColor: "rgba(239, 68, 68, 0.25)",
                    borderWidth: 1,
                    pointRadius: 0,
                    fill: false
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    min: 0,
                    max: 100,
                    title: { display: true, text: "Utilization (%)" }
                },
                x: {
                    title: { display: true, text: "Forecast Horizon" }
                }
            },
            plugins: {
                legend: { position: "top" }
            }
        }
    });
}

// ============================================================
// PHASE 24: FILE INTEGRITY MONITORING (FIM) DASHBOARD
// ============================================================

async function loadFimData() {
    const activeHost = currentFleetHost || "localhost";
    try {
        // 1. Load FIM Stats
        const statsRes = await apiFetch(`/fim/stats?hostname=${encodeURIComponent(activeHost)}`);
        if (statsRes && statsRes.ok) {
            const stats = await statsRes.json();
            const baseCountEl = document.getElementById("fimBaselinedCount");
            const violCountEl = document.getElementById("fimViolationCount");
            const critCountEl = document.getElementById("fimCriticalCount");
            const healthEl = document.getElementById("fimBaselineHealth");

            if (baseCountEl) baseCountEl.textContent = stats.monitored_files_count ?? 0;
            if (violCountEl) violCountEl.textContent = stats.total_integrity_events ?? 0;
            if (critCountEl) critCountEl.textContent = stats.critical_events_count ?? 0;
            if (healthEl) {
                if (stats.baseline_healthy) {
                    healthEl.textContent = "VERIFIED";
                    healthEl.style.color = "#16a34a";
                } else {
                    healthEl.textContent = "INTEGRITY BREACH";
                    healthEl.style.color = "#dc2626";
                }
            }
        }

        // 2. Load Events Table
        const eventsRes = await apiFetch(`/fim/events?hostname=${encodeURIComponent(activeHost)}&limit=25`);
        const tbody = document.getElementById("fimEventsTable");
        if (!tbody) return;

        if (eventsRes && eventsRes.ok) {
            const events = await eventsRes.json();
            tbody.textContent = "";

            if (!events || events.length === 0) {
                const tr = document.createElement("tr");
                const td = document.createElement("td");
                td.colSpan = 7;
                td.textContent = "No integrity violation events detected. Monitored baselines intact.";
                tr.appendChild(td);
                tbody.appendChild(tr);
                return;
            }

            events.forEach(ev => {
                const tr = document.createElement("tr");

                const sevColor = ev.severity === "CRITICAL" ? "#dc2626" :
                                 ev.severity === "HIGH" ? "#ea580c" :
                                 ev.severity === "MEDIUM" ? "#d97706" : "#16a34a";

                const typeColor = ev.change_type === "DELETED" ? "#dc2626" :
                                  ev.change_type === "MODIFIED" ? "#ea580c" :
                                  ev.change_type === "CREATED" ? "#2563eb" : "#7c3aed";

                const timeStr = ev.detected_at ? new Date(ev.detected_at).toLocaleString() : "-";

                let diffText = "-";
                if (ev.change_type === "MODIFIED") {
                    diffText = `Hash: ${ev.old_sha256 ? ev.old_sha256.substring(0, 8) : 'none'} → ${ev.new_sha256 ? ev.new_sha256.substring(0, 8) : 'none'}`;
                } else if (ev.change_type === "PERMISSION_CHANGED") {
                    diffText = `Perm: ${ev.old_permissions || '-'} → ${ev.new_permissions || '-'}`;
                } else if (ev.change_type === "OWNERSHIP_CHANGED") {
                    diffText = `Owner: ${ev.old_owner || '-'} → ${ev.new_owner || '-'}`;
                }

                tr.innerHTML = `
                    <td style="font-size: 12px; color: #64748b;">${escapeHtml(timeStr)}</td>
                    <td style="font-weight: 500;">${escapeHtml(ev.hostname || activeHost)}</td>
                    <td style="font-family: monospace; font-weight: bold; color: #1e293b;">${escapeHtml(ev.file_path)}</td>
                    <td><span style="color: white; background: ${typeColor}; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: bold;">${escapeHtml(ev.change_type)}</span></td>
                    <td><span style="color: white; background: ${sevColor}; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: bold;">${escapeHtml(ev.severity)}</span></td>
                    <td style="font-family: monospace; font-size: 12px;">${escapeHtml(diffText)}</td>
                    <td style="font-size: 12px; color: #475569;">${escapeHtml(ev.details || "-")}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error("Error loading FIM data:", err);
    }
}

async function triggerFimScan() {
    const activeHost = currentFleetHost || "localhost";
    try {
        const res = await apiFetch("/fim/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hostname: activeHost })
        });
        if (res && res.ok) {
            const data = await res.json();
            alert(`Integrity scan completed. Scanned ${data.scanned_files_count} files, detected ${data.violations_detected} violations.`);
            loadFimData();
        } else {
            alert("Scan failed. Verify analyst or admin privileges.");
        }
    } catch (err) {
        alert(`Error triggering scan: ${err.message}`);
    }
}

// ============================================================
// PHASE 25 - PROCESS AND SERVICE MONITORING
// ============================================================

async function loadProcessData() {
    const activeHost = currentFleetHost || "localhost";
    const encodedHost = encodeURIComponent(activeHost);
    try {
        // 1. Fetch Stats
        const statsRes = await apiFetch(`/processes/stats?hostname=${encodedHost}`);
        if (statsRes && statsRes.ok) {
            const stats = await statsRes.json();
            const totalEl = document.getElementById("procTotalCount");
            const highResEl = document.getElementById("procHighResCount");
            const suspEl = document.getElementById("procSuspiciousCount");
            const failedServEl = document.getElementById("serviceFailedCount");

            if (totalEl) totalEl.textContent = stats.running_processes_count ?? 0;
            if (highResEl) highResEl.textContent = stats.high_cpu_processes_count ?? 0;
            if (suspEl) suspEl.textContent = stats.suspicious_processes_count ?? 0;
            if (failedServEl) failedServEl.textContent = stats.failed_services_count ?? 0;
        }

        // 2. Fetch Top Processes
        const procRes = await apiFetch(`/processes?hostname=${encodedHost}&limit=15`);
        const procTable = document.getElementById("topProcessesTable");
        if (procRes && procRes.ok && procTable) {
            const procs = await procRes.json();
            procTable.innerHTML = "";
            if (!procs || procs.length === 0) {
                procTable.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #64748b;">No active processes recorded.</td></tr>`;
            } else {
                procs.forEach(p => {
                    const tr = document.createElement("tr");
                    const isSuspicious = p.is_suspicious;
                    const threatCat = p.threat_category || "BENIGN";
                    const isThreat = threatCat !== "BENIGN";

                    const badge = isThreat 
                        ? `<span style="background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px;">${escapeHtml(threatCat)}</span>`
                        : `<span style="color: #16a34a; font-size: 12px;">✓ Normal</span>`;

                    tr.innerHTML = `
                        <td style="font-family: monospace; font-weight: bold;">${p.pid}</td>
                        <td>${escapeHtml(p.username || "-")}</td>
                        <td style="font-family: monospace; font-weight: 500;">${escapeHtml(p.process_name || p.name || "-")}</td>
                        <td><strong>${p.cpu_percent ? p.cpu_percent.toFixed(1) : 0.0}%</strong></td>
                        <td>${p.memory_percent ? p.memory_percent.toFixed(1) : 0.0}%</td>
                        <td><span style="font-size: 12px; color: #475569;">${escapeHtml(p.status || "R")}</span></td>
                        <td><span style="font-weight: bold; color: ${isThreat ? '#dc2626' : '#16a34a'};">${isThreat ? 'HIGH' : 'LOW'}</span></td>
                        <td>${badge}</td>
                    `;
                    procTable.appendChild(tr);
                });
            }
        }

        // 3. Fetch Alerts
        const alertRes = await apiFetch(`/processes/alerts?hostname=${encodedHost}&limit=10`);
        const alertTable = document.getElementById("procAlertsTable");
        if (alertRes && alertRes.ok && alertTable) {
            const alerts = await alertRes.json();
            alertTable.innerHTML = "";
            if (!alerts || alerts.length === 0) {
                alertTable.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #16a34a; font-weight: 500;">✓ No active process security anomalies detected.</td></tr>`;
            } else {
                alerts.forEach(al => {
                    const tr = document.createElement("tr");
                    const sevColor = al.severity === "CRITICAL" ? "#dc2626" :
                                     al.severity === "HIGH" ? "#ea580c" :
                                     al.severity === "MEDIUM" ? "#d97706" : "#16a34a";
                    const timeStr = al.created_at ? new Date(al.created_at).toLocaleTimeString() : "-";

                    tr.innerHTML = `
                        <td style="font-size: 12px; color: #64748b;">${escapeHtml(timeStr)}</td>
                        <td>${escapeHtml(al.hostname || activeHost)}</td>
                        <td style="font-weight: 500;">${escapeHtml(al.alert_type)}</td>
                        <td style="font-family: monospace; font-weight: bold;">${escapeHtml(al.process_name || "-")} (PID: ${al.pid || "-"})</td>
                        <td><span style="color: white; background: ${sevColor}; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: bold;">${escapeHtml(al.severity)}</span></td>
                        <td><span style="font-family: monospace; font-size: 11px; background: #f1f5f9; padding: 2px 5px; border-radius: 3px;">T1059</span></td>
                        <td style="font-size: 12px; color: #334155;">${escapeHtml(al.details || al.description || "-")}</td>
                    `;
                    alertTable.appendChild(tr);
                });
            }
        }

        // 4. Fetch Systemd Services
        const servRes = await apiFetch(`/processes/services?hostname=${encodedHost}`);
        const servTable = document.getElementById("systemdServicesTable");
        if (servRes && servRes.ok && servTable) {
            const servs = await servRes.json();
            servTable.innerHTML = "";
            if (!servs || servs.length === 0) {
                servTable.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #64748b;">No systemd services tracked.</td></tr>`;
            } else {
                servs.forEach(s => {
                    const tr = document.createElement("tr");
                    const isFailed = s.is_failed || s.active_state === "failed" || s.sub_state === "failed";
                    const statusColor = isFailed ? "#dc2626" :
                                        s.active_state === "active" ? "#16a34a" : "#64748b";

                    tr.innerHTML = `
                        <td>${escapeHtml(s.hostname || activeHost)}</td>
                        <td style="font-family: monospace; font-weight: bold;">${escapeHtml(s.service_name || s.unit_name)}</td>
                        <td>${escapeHtml(s.load_state || "loaded")}</td>
                        <td><span style="color: ${statusColor}; font-weight: bold;">${escapeHtml(s.active_state)}</span></td>
                        <td><span style="font-size: 12px;">${escapeHtml(s.sub_state || "-")}</span></td>
                        <td><span style="color: #2563eb; font-weight: bold;">YES</span></td>
                        <td><span style="color: ${statusColor}; font-weight: 500;">${isFailed ? '⚠ ATTENTION REQUIRED' : '✓ Normal'}</span></td>
                    `;
                    servTable.appendChild(tr);
                });
            }
        }

    } catch (err) {
        console.error("Error loading process monitoring data:", err);
    }
}

async function triggerProcessScan() {
    const activeHost = currentFleetHost || "localhost";
    try {
        const res = await apiFetch("/processes/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hostname: activeHost })
        });
        if (res && res.ok) {
            const data = await res.json();
            alert(`Process scan complete. Scanned ${data.total_processes} processes. Suspicious: ${data.suspicious_count}, New alerts: ${data.new_alerts_emitted}`);
            loadProcessData();
        } else {
            alert("Scan failed. Verify analyst or admin privileges.");
        }
    } catch (err) {
        alert(`Error triggering process scan: ${err.message}`);
    }
}

async function triggerServiceScan() {
    await triggerProcessScan();
}

// ============================================================
// PHASE 26 - NETWORK SECURITY MONITORING
// ============================================================

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

async function loadNetworkData() {
    const activeHost = currentFleetHost || "localhost";
    const encodedHost = encodeURIComponent(activeHost);
    try {
        // 1. Fetch Stats
        const statsRes = await apiFetch(`/network/stats?hostname=${encodedHost}`);
        if (statsRes && statsRes.ok) {
            const stats = await statsRes.json();
            const activeEl = document.getElementById("netActiveConnCount");
            const listenEl = document.getElementById("netListeningPortCount");
            const suspEl = document.getElementById("netSuspiciousConnCount");
            const unauthEl = document.getElementById("netUnauthorizedPortCount");
            const txEl = document.getElementById("netBytesSentCount");
            const rxEl = document.getElementById("netBytesRecvCount");

            if (activeEl) activeEl.textContent = stats.active_connections_count ?? 0;
            if (listenEl) listenEl.textContent = stats.listening_ports_count ?? 0;
            if (suspEl) suspEl.textContent = stats.suspicious_connections_count ?? 0;
            if (unauthEl) unauthEl.textContent = stats.unauthorized_ports_count ?? 0;
            if (txEl) txEl.textContent = formatBytes(stats.total_bytes_sent);
            if (rxEl) rxEl.textContent = formatBytes(stats.total_bytes_recv);
        }

        // 2. Fetch Listening Ports
        const portsRes = await apiFetch(`/network/ports?hostname=${encodedHost}`);
        const portsTable = document.getElementById("listeningPortsTable");
        if (portsRes && portsRes.ok && portsTable) {
            const ports = await portsRes.json();
            portsTable.innerHTML = "";
            if (!ports || ports.length === 0) {
                portsTable.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #64748b;">No open listening ports detected.</td></tr>`;
            } else {
                ports.forEach(p => {
                    const tr = document.createElement("tr");
                    const isAuth = p.is_authorized;
                    const riskColor = p.risk_level === "CRITICAL" ? "#dc2626" :
                                      p.risk_level === "HIGH" ? "#ea580c" :
                                      p.risk_level === "MEDIUM" ? "#d97706" : "#16a34a";

                    tr.innerHTML = `
                        <td>${escapeHtml(p.hostname || activeHost)}</td>
                        <td><span style="font-weight: bold; text-transform: uppercase;">${escapeHtml(p.protocol)}</span></td>
                        <td style="font-family: monospace;">${escapeHtml(p.bind_address)}</td>
                        <td style="font-family: monospace; font-weight: bold; color: #1e293b;">${p.port}</td>
                        <td><span style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 500;">${escapeHtml(p.service_hint || "Custom")}</span></td>
                        <td style="font-size: 12px;">${escapeHtml(p.process_name || "-")} (PID: ${p.pid || "-"})</td>
                        <td><span style="font-weight: bold; color: ${isAuth ? '#16a34a' : '#dc2626'};">${isAuth ? '✓ Authorized' : '⚠ Unexpected'}</span></td>
                        <td><span style="color: white; background: ${riskColor}; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: bold;">${escapeHtml(p.risk_level || "LOW")}</span></td>
                    `;
                    portsTable.appendChild(tr);
                });
            }
        }

        // 3. Fetch Active Connections
        const connRes = await apiFetch(`/network/connections?hostname=${encodedHost}&limit=20`);
        const connTable = document.getElementById("activeConnectionsTable");
        if (connRes && connRes.ok && connTable) {
            const conns = await connRes.json();
            connTable.innerHTML = "";
            if (!conns || conns.length === 0) {
                connTable.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #64748b;">No active connections recorded.</td></tr>`;
            } else {
                conns.forEach(c => {
                    const tr = document.createElement("tr");
                    const isSusp = c.is_suspicious;
                    const rAddr = c.remote_address ? `${c.remote_address}:${c.remote_port}` : "*:*";
                    const lAddr = `${c.local_address}:${c.local_port}`;

                    tr.innerHTML = `
                        <td style="text-transform: uppercase; font-size: 12px; font-weight: bold;">${escapeHtml(c.protocol)}</td>
                        <td style="font-family: monospace; font-size: 12px;">${escapeHtml(lAddr)}</td>
                        <td style="font-family: monospace; font-size: 12px; font-weight: bold;">${escapeHtml(rAddr)}</td>
                        <td><span style="font-size: 11px; background: #f8fafc; padding: 2px 6px; border: 1px solid #e2e8f0; border-radius: 4px;">${escapeHtml(c.status)}</span></td>
                        <td style="font-size: 12px;">${escapeHtml(c.process_name || "-")} (${c.pid || "-"})</td>
                        <td><span style="font-weight: bold; color: ${isSusp ? '#dc2626' : '#16a34a'};">${isSusp ? '⚠ ' + escapeHtml(c.threat_description) : '✓ Normal'}</span></td>
                        <td><strong style="color: ${isSusp ? '#dc2626' : '#64748b'};">${c.risk_score || 0}</strong></td>
                    `;
                    connTable.appendChild(tr);
                });
            }
        }

        // 4. Fetch Network Alerts
        const alertRes = await apiFetch(`/network/alerts?hostname=${encodedHost}&limit=10`);
        const alertTable = document.getElementById("netAlertsTable");
        if (alertRes && alertRes.ok && alertTable) {
            const alerts = await alertRes.json();
            alertTable.innerHTML = "";
            if (!alerts || alerts.length === 0) {
                alertTable.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #16a34a; font-weight: 500;">✓ No active network anomalies detected.</td></tr>`;
            } else {
                alerts.forEach(al => {
                    const tr = document.createElement("tr");
                    const sevColor = al.severity === "CRITICAL" ? "#dc2626" :
                                     al.severity === "HIGH" ? "#ea580c" :
                                     al.severity === "MEDIUM" ? "#d97706" : "#16a34a";
                    const timeStr = al.created_at ? new Date(al.created_at).toLocaleTimeString() : "-";
                    const endpoints = al.destination_ip ? `${al.source_ip}:${al.source_port} → ${al.destination_ip}:${al.destination_port}` : `${al.source_ip || "-"}:${al.source_port || "-"}`;

                    tr.innerHTML = `
                        <td style="font-size: 12px; color: #64748b;">${escapeHtml(timeStr)}</td>
                        <td>${escapeHtml(al.hostname || activeHost)}</td>
                        <td style="font-weight: 500;">${escapeHtml(al.alert_type)}</td>
                        <td style="font-family: monospace; font-size: 11px;">${escapeHtml(endpoints)}</td>
                        <td><span style="text-transform: uppercase; font-size: 11px;">${escapeHtml(al.protocol || "TCP")}</span></td>
                        <td><span style="color: white; background: ${sevColor}; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: bold;">${escapeHtml(al.severity)}</span></td>
                        <td><span style="font-family: monospace; font-size: 11px; background: #f1f5f9; padding: 2px 5px; border-radius: 3px;">${escapeHtml(al.mitre_technique || "-")}</span></td>
                        <td style="font-size: 12px; color: #334155;">${escapeHtml(al.description)}</td>
                    `;
                    alertTable.appendChild(tr);
                });
            }
        }

        // 5. Fetch Interfaces
        const ifaceRes = await apiFetch(`/network/interfaces?hostname=${encodedHost}`);
        const ifaceTable = document.getElementById("networkInterfacesTable");
        if (ifaceRes && ifaceRes.ok && ifaceTable) {
            const ifaces = await ifaceRes.json();
            ifaceTable.innerHTML = "";
            if (!ifaces || ifaces.length === 0) {
                ifaceTable.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #64748b;">No interfaces detected.</td></tr>`;
            } else {
                ifaces.forEach(i => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td style="font-family: monospace; font-weight: bold;">${escapeHtml(i.interface_name)}</td>
                        <td><span style="color: ${i.is_up ? '#16a34a' : '#dc2626'}; font-weight: bold;">${i.is_up ? 'UP' : 'DOWN'}</span></td>
                        <td>${i.speed_mbps ?? 0} Mbps</td>
                        <td>${formatBytes(i.bytes_sent ?? 0)}</td>
                        <td>${formatBytes(i.bytes_recv ?? 0)}</td>
                        <td style="font-size: 12px;">↓ ${(i.packets_recv ?? 0).toLocaleString()} / ↑ ${(i.packets_sent ?? 0).toLocaleString()}</td>
                        <td style="font-size: 12px; color: ${((i.dropin || 0) > 0 || (i.dropout || 0) > 0 || (i.errin || 0) > 0) ? '#dc2626' : '#16a34a'};">
                            ${((i.dropin || 0) > 0 || (i.dropout || 0) > 0 || (i.errin || 0) > 0) ? `Drops: ${(i.dropin || 0) + (i.dropout || 0)}, Errs: ${i.errin || 0}` : '✓ 0 errors'}
                        </td>
                    `;
                    ifaceTable.appendChild(tr);
                });
            }
        }

    } catch (err) {
        console.error("Error loading network security data:", err);
    }
}

async function triggerNetworkScan() {
    const activeHost = currentFleetHost || "localhost";
    try {
        const res = await apiFetch("/network/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hostname: activeHost })
        });
        if (res && res.ok) {
            const data = await res.json();
            alert(`Network scan complete. Scanned ${data.interfaces_count} interfaces, ${data.total_connections} sockets, ${data.listening_ports_count} listening ports. New alerts: ${data.new_alerts_emitted}`);
            loadNetworkData();
        } else {
            alert("Scan failed. Verify analyst or admin privileges.");
        }
    } catch (err) {
        alert(`Error triggering network scan: ${err.message}`);
    }
}

// ============================================================
// PHASE 27 - MULTI-SERVER EXPANSION & FLEET MANAGEMENT
// ============================================================

// (currentFleetHost initialized near top as "localhost")

async function loadFleetData() {
    try {
        // 1. Fetch Fleet Health
        const healthRes = await apiFetch("/multihost/fleet/health");
        if (healthRes && healthRes.ok) {
            const h = await healthRes.json();
            const totEl = document.getElementById("fleetTotalServers");
            const onEl = document.getElementById("fleetOnlineCount");
            const offEl = document.getElementById("fleetOfflineCount");
            const cpuEl = document.getElementById("fleetAvgCpu");
            const memEl = document.getElementById("fleetAvgMem");
            const latEl = document.getElementById("fleetAvgLatency");

            if (totEl) totEl.textContent = h.total_servers ?? 0;
            if (onEl) onEl.textContent = h.online_count ?? 0;
            if (offEl) offEl.textContent = (h.offline_count + h.degraded_count) ?? 0;
            if (cpuEl) cpuEl.textContent = `${h.average_cpu_percent ?? 0}%`;
            if (memEl) memEl.textContent = `${h.average_memory_percent ?? 0}%`;
            if (latEl) latEl.textContent = `${h.average_latency_ms ?? 0} ms`;
        }

        // 2. Fetch Server List
        const serversRes = await apiFetch("/multihost/servers");
        const table = document.getElementById("fleetServersTable");
        const selector = document.getElementById("fleetHostSelector");

        if (serversRes && serversRes.ok) {
            const servers = await serversRes.json();

            // Populate selector if needed
            if (selector && servers && servers.length > 0) {
                const currentVal = selector.value;
                selector.innerHTML = "";
                servers.forEach(s => {
                    const opt = document.createElement("option");
                    opt.value = s.hostname;
                    opt.textContent = `${s.hostname} (${s.display_name})`;
                    if (s.hostname === currentFleetHost) {
                        opt.selected = true;
                    }
                    selector.appendChild(opt);
                });
            }

            // Populate Table
            if (table) {
                table.innerHTML = "";
                if (!servers || servers.length === 0) {
                    table.innerHTML = `<tr><td colspan="10" style="text-align: center; color: #64748b;">No servers registered in fleet.</td></tr>`;
                } else {
                    servers.forEach(s => {
                        const tr = document.createElement("tr");
                        const isOnline = s.status === "ONLINE";
                        const statusColor = isOnline ? "#16a34a" :
                                            s.status === "DEGRADED" ? "#ea580c" : "#dc2626";

                        const envBadgeColor = s.environment === "production" ? "#2563eb" :
                                              s.environment === "dmz" ? "#dc2626" : "#475569";

                        tr.innerHTML = `
                            <td style="font-family: monospace; font-weight: bold; color: #0f172a;">${escapeHtml(s.hostname)}</td>
                            <td>${escapeHtml(s.display_name)}</td>
                            <td style="font-family: monospace; font-size: 12px;">${escapeHtml(s.ip_address)}:${s.ssh_port}</td>
                            <td><span style="color: white; background: ${envBadgeColor}; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase;">${escapeHtml(s.environment)}</span></td>
                            <td><span style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 11px;">${escapeHtml(s.host_group)}</span></td>
                            <td style="font-size: 12px;">${escapeHtml(s.os_flavor)}</td>
                            <td><span style="color: white; background: ${statusColor}; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: bold;">${escapeHtml(s.status)}</span></td>
                            <td style="font-size: 12px;">CPU: <strong>${s.cpu_usage}%</strong> / RAM: <strong>${s.memory_usage}%</strong></td>
                            <td style="font-family: monospace; font-size: 12px;">${s.latency_ms} ms</td>
                            <td>
                                <button type="button" onclick="switchActiveHost('${escapeHtml(s.hostname)}')" style="padding: 3px 8px; font-size: 11px; background: #0077cc; color: white; border: none; border-radius: 4px; cursor: pointer;">Focus</button>
                                <button type="button" onclick="pingServerDirect('${escapeHtml(s.hostname)}')" style="padding: 3px 8px; font-size: 11px; background: #0891b2; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 4px;">Ping</button>
                            </td>
                        `;
                        table.appendChild(tr);
                    });
                }
            }
        }
    } catch (err) {
        console.error("Error loading multi-server fleet data:", err);
    }
}

function switchActiveHost(hostname) {
    currentFleetHost = hostname || "localhost";
    const selector = document.getElementById("fleetHostSelector");
    if (selector) selector.value = currentFleetHost;
    console.log(`Switched active monitoring target to: ${currentFleetHost}`);
    // Trigger refreshes for active host across all host-scoped panels
    loadPredictiveAnalytics();
    loadFimData();
    loadProcessData();
    loadNetworkData();
}

async function pingActiveServer() {
    await pingServerDirect(currentFleetHost);
}

async function pingServerDirect(hostname) {
    try {
        const res = await apiFetch(`/multihost/servers/${encodeURIComponent(hostname)}/ping`, {
            method: "POST"
        });
        if (res && res.ok) {
            const data = await res.json();
            alert(`Heartbeat probe to ${data.hostname}: Status=${data.status}, Latency=${data.latency_ms} ms`);
            loadFleetData();
        } else {
            alert(`Failed to probe ${hostname}. Verify server permissions.`);
        }
    } catch (err) {
        alert(`Error pinging server: ${err.message}`);
    }
}

// ============================================================
// PHASE 28 - WHAT-IF ATTACK SIMULATION
// ============================================================

async function loadSimulationData() {
    try {
        // 1. Fetch Stats
        const statsRes = await apiFetch("/simulation/stats");
        if (statsRes && statsRes.ok) {
            const s = await statsRes.json();
            const totEl = document.getElementById("simTotalCount");
            const critEl = document.getElementById("simCriticalCount");
            const riskEl = document.getElementById("simAvgRisk");
            const contEl = document.getElementById("simAvgContainment");

            if (totEl) totEl.textContent = s.total_simulations_conducted ?? 0;
            if (critEl) critEl.textContent = s.critical_scenario_runs ?? 0;
            if (riskEl) riskEl.textContent = `${s.average_risk_score ?? 0} / 100`;
            if (contEl) contEl.textContent = `${s.average_containment_rate ?? 0}%`;
        }

        // 2. Fetch History
        const histRes = await apiFetch("/simulation/history?limit=15");
        const table = document.getElementById("simHistoryTable");
        if (histRes && histRes.ok && table) {
            const history = await histRes.json();
            table.innerHTML = "";
            if (!history || history.length === 0) {
                table.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #64748b;">No simulation exercises recorded.</td></tr>`;
            } else {
                history.forEach(sim => {
                    const tr = document.createElement("tr");
                    const riskColor = sim.risk_score >= 85 ? "#dc2626" :
                                      sim.risk_score >= 60 ? "#ea580c" : "#16a34a";

                    tr.innerHTML = `
                        <td style="font-family: monospace; font-size: 11px; font-weight: bold; color: #2563eb;">${escapeHtml(sim.simulation_id)}</td>
                        <td style="font-weight: 500;">${escapeHtml(sim.scenario_name)}</td>
                        <td style="font-family: monospace;">${escapeHtml(sim.target_hostname)}</td>
                        <td><span style="font-family: monospace; font-size: 11px; background: #f1f5f9; padding: 2px 6px; border-radius: 4px;">${escapeHtml(sim.mitre_technique)}</span></td>
                        <td><span style="font-size: 12px; color: #475569;">${escapeHtml(sim.tactics)}</span></td>
                        <td style="font-size: 12px;">${escapeHtml(sim.simulated_by)}</td>
                        <td><strong style="color: ${riskColor};">${sim.risk_score}</strong></td>
                        <td><span style="color: #16a34a; font-weight: bold;">${sim.predicted_containment_probability}%</span></td>
                        <td><span style="color: white; background: #16a34a; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: bold;">${escapeHtml(sim.status)}</span></td>
                    `;
                    table.appendChild(tr);
                });
            }
        }
    } catch (err) {
        console.error("Error loading attack simulation data:", err);
    }
}

async function triggerSimulationRun() {
    const scenarioSelector = document.getElementById("simScenarioSelector");
    const scenarioId = scenarioSelector ? scenarioSelector.value : "SSH_BRUTE_FORCE";
    const targetHost = currentFleetHost || "localhost";

    try {
        const res = await apiFetch("/simulation/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                scenario_id: scenarioId,
                target_hostname: targetHost
            })
        });

        if (res && res.ok) {
            const data = await res.json();
            displaySimulationResult(data);
            loadSimulationData();
        } else {
            alert("Simulation failed to execute. Verify admin/analyst privileges.");
        }
    } catch (err) {
        alert(`Error executing simulation: ${err.message}`);
    }
}

function displaySimulationResult(sim) {
    const box = document.getElementById("simResultBox");
    const title = document.getElementById("simResTitle");
    const badge = document.getElementById("simResRiskBadge");
    const summary = document.getElementById("simResSummary");
    const mttd = document.getElementById("simResMttd");
    const mttr = document.getElementById("simResMttr");
    const prob = document.getElementById("simResProb");
    const recsList = document.getElementById("simResRecs");

    if (box) box.style.display = "block";
    if (title) title.textContent = `Simulation: ${sim.scenario_name} (Target: ${sim.target_hostname})`;
    if (badge) {
        badge.textContent = `Risk: ${sim.risk_score} (${sim.impact_level})`;
        badge.style.background = sim.risk_score >= 80 ? "#dc2626" : "#ea580c";
    }
    if (summary) summary.textContent = sim.impact_summary;
    if (mttd) mttd.textContent = `${sim.estimated_mttd_seconds} seconds`;
    if (mttr) mttr.textContent = `${sim.estimated_mttr_seconds} seconds`;
    if (prob) prob.textContent = `${sim.predicted_containment_probability}%`;

    if (recsList) {
        recsList.innerHTML = "";
        (sim.defensive_recommendations || []).forEach(r => {
            const li = document.createElement("li");
            li.textContent = r;
            recsList.appendChild(li);
        });
    }

    if (box) box.scrollIntoView({ behavior: "smooth" });
}

// ============================================================
// PHASE 29 - ADVANCED INCIDENT RESPONSE & PLAYBOOKS
// ============================================================

async function loadIncidentResponseData() {
    try {
        // 1. Fetch Stats
        const statsRes = await apiFetch("/incident-response/stats");
        if (statsRes && statsRes.ok) {
            const s = await statsRes.json();
            const totEl = document.getElementById("irTotalExecutions");
            const sucEl = document.getElementById("irSuccessCount");
            const blkEl = document.getElementById("irSafeguardBlocks");
            const eviEl = document.getElementById("irEvidenceCount");

            if (totEl) totEl.textContent = s.total_playbook_executions ?? 0;
            if (sucEl) sucEl.textContent = s.successful_executions ?? 0;
            if (blkEl) blkEl.textContent = s.blocked_by_safeguards ?? 0;
            if (eviEl) eviEl.textContent = s.evidence_artifacts_secured ?? 0;
        }

        // 2. Fetch Playbook History
        const histRes = await apiFetch("/incident-response/playbooks/history?limit=15");
        const histTable = document.getElementById("playbookHistoryTable");
        if (histRes && histRes.ok && histTable) {
            const history = await histRes.json();
            histTable.innerHTML = "";
            if (!history || history.length === 0) {
                histTable.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #64748b;">No playbook execution history.</td></tr>`;
            } else {
                history.forEach(run => {
                    const tr = document.createElement("tr");
                    const isSuccess = run.status === "SUCCESS";
                    const statusColor = isSuccess ? "#16a34a" : "#dc2626";
                    const modeBg = run.mode === "LIVE" ? "#dc2626" : "#475569";
                    const timeStr = run.executed_at ? new Date(run.executed_at).toLocaleTimeString() : "-";

                    tr.innerHTML = `
                        <td style="font-family: monospace; font-size: 11px; font-weight: bold; color: #2563eb;">${escapeHtml(run.execution_id)}</td>
                        <td style="font-weight: 500;">${escapeHtml(run.playbook_name)}</td>
                        <td style="font-family: monospace;">${escapeHtml(run.target_hostname)}</td>
                        <td><span style="color: white; background: ${modeBg}; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">${escapeHtml(run.mode)}</span></td>
                        <td><span style="color: ${run.safeguards_passed ? '#16a34a' : '#dc2626'}; font-size: 12px; font-weight: bold;">${run.safeguards_passed ? '✓ Passed' : '⚠ Blocked'}</span></td>
                        <td><span style="color: white; background: ${statusColor}; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: bold;">${escapeHtml(run.status)}</span></td>
                        <td style="font-size: 12px;">${escapeHtml(run.executed_by)}</td>
                        <td style="font-size: 12px; color: #334155;">${escapeHtml(run.result_summary || "-")}</td>
                        <td style="font-size: 11px; color: #64748b;">${escapeHtml(timeStr)}</td>
                    `;
                    histTable.appendChild(tr);
                });
            }
        }

        // 3. Fetch Timeline for inc-2026-001
        const timeRes = await apiFetch("/incident-response/timeline/inc-2026-001");
        const timeTable = document.getElementById("incidentTimelineTable");
        if (timeRes && timeRes.ok && timeTable) {
            const events = await timeRes.json();
            timeTable.innerHTML = "";
            if (!events || events.length === 0) {
                timeTable.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #64748b;">No timeline events recorded.</td></tr>`;
            } else {
                events.forEach(ev => {
                    const tr = document.createElement("tr");
                    const sevColor = ev.severity === "CRITICAL" ? "#dc2626" :
                                     ev.severity === "HIGH" ? "#ea580c" : "#2563eb";
                    const tStr = ev.event_timestamp ? new Date(ev.event_timestamp).toLocaleTimeString() : "-";

                    tr.innerHTML = `
                        <td style="font-size: 11px; color: #64748b;">${escapeHtml(tStr)}</td>
                        <td><span style="font-size: 11px; background: #f1f5f9; padding: 2px 5px; border-radius: 3px; font-weight: 500;">${escapeHtml(ev.event_type)}</span></td>
                        <td style="font-weight: 500;">${escapeHtml(ev.title)}</td>
                        <td><span style="color: ${sevColor}; font-weight: bold; font-size: 11px;">${escapeHtml(ev.severity)}</span></td>
                        <td style="font-size: 12px; color: #475569;">${escapeHtml(ev.details || "-")}</td>
                    `;
                    timeTable.appendChild(tr);
                });
            }
        }

        // 4. Fetch Evidence for inc-2026-001
        const eviRes = await apiFetch("/incident-response/evidence/inc-2026-001");
        const eviTable = document.getElementById("incidentEvidenceTable");
        if (eviRes && eviRes.ok && eviTable) {
            const artifacts = await eviRes.json();
            eviTable.innerHTML = "";
            if (!artifacts || artifacts.length === 0) {
                eviTable.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #64748b;">No evidence artifacts attached.</td></tr>`;
            } else {
                artifacts.forEach(art => {
                    const tr = document.createElement("tr");
                    const hashShort = art.file_hash_sha256 ? `${art.file_hash_sha256.substring(0, 12)}...` : "-";

                    tr.innerHTML = `
                        <td style="font-family: monospace; font-size: 11px; font-weight: bold;">${escapeHtml(art.artifact_id)}</td>
                        <td><span style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 11px;">${escapeHtml(art.artifact_type)}</span></td>
                        <td style="font-family: monospace; font-weight: 500;">${escapeHtml(art.file_name)}</td>
                        <td style="font-family: monospace; font-size: 11px; color: #64748b;">${escapeHtml(hashShort)}</td>
                        <td style="font-size: 12px;">${escapeHtml(art.collected_by)}</td>
                    `;
                    eviTable.appendChild(tr);
                });
            }
        }

    } catch (err) {
        console.error("Error loading incident response data:", err);
    }
}

async function triggerPlaybookExecution() {
    const pbSelector = document.getElementById("playbookSelector");
    const modeSelector = document.getElementById("playbookModeSelector");
    const paramInput = document.getElementById("playbookParamInput");

    const pbId = pbSelector ? pbSelector.value : "BLOCK_MALICIOUS_IP";
    const mode = modeSelector ? modeSelector.value : "DRY_RUN";
    const paramVal = paramInput ? paramInput.value.trim() : "";
    const targetHost = currentFleetHost || "localhost";

    // Map parameters based on playbook
    const params = {};
    if (pbId === "BLOCK_MALICIOUS_IP") {
        params.ip_address = paramVal || "198.51.100.2";
    } else if (pbId === "ISOLATE_HOST_VLAN") {
        params.target_hostname = targetHost;
        params.confirm_isolation = true;
    } else if (pbId === "KILL_ROGUE_PROCESS") {
        const parts = paramVal.split(" ");
        params.pid = parseInt(parts[0]) || 9999;
        params.process_name = parts[1] || "xmrig";
    } else if (pbId === "RESTORE_FIM_FILE") {
        params.file_path = paramVal || "/etc/sudoers";
    } else if (pbId === "RESET_COMPROMISED_CREDENTIALS") {
        params.username = paramVal || "compromised_user";
    } else if (pbId === "RESTART_FAILED_SERVICE") {
        params.service_name = paramVal || "sshd.service";
    }

    try {
        const res = await apiFetch("/incident-response/playbooks/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                playbook_id: pbId,
                target_hostname: targetHost,
                incident_id: "inc-2026-001",
                mode: mode,
                parameters: params
            })
        });

        if (res && res.ok) {
            const data = await res.json();
            alert(`Playbook Execution: Status=${data.status}\nSafeguards Passed: ${data.safeguards_passed}\nSummary: ${data.result_summary}`);
            loadIncidentResponseData();
        } else {
            alert("Playbook execution failed. Verify analyst/admin privileges.");
        }
    } catch (err) {
        alert(`Error executing playbook: ${err.message}`);
    }
}
