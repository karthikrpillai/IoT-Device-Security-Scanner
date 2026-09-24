let devices = [];


fetch("/network")
    .then(response => response.json())
    .then(data => {
        document.getElementById("network").value = data.network;
    });


function startScan() {
    const network = document.getElementById("network").value;
    const button = document.getElementById("scanButton");

    document.getElementById("status").textContent = "Scanning... please wait";
    document.getElementById("errorMessage").textContent = "";
    document.getElementById("detailsBox").style.display = "none";
    button.disabled = true;

    fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ network: network })
    })
        .then(response => response.json())
        .then(data => {
            button.disabled = false;

            if (data.error) {
                document.getElementById("status").textContent = "Error";
                document.getElementById("errorMessage").textContent = data.error;
                return;
            }

            document.getElementById("status").textContent = "Completed";
            showResults(data);
        })
        .catch(() => {
            button.disabled = false;
            document.getElementById("status").textContent = "Error";
            document.getElementById("errorMessage").textContent = "Could not connect to the server.";
        });
}


function showResults(data) {
    devices = data.devices;

    document.getElementById("devicesFound").textContent = data.devices_found;
    document.getElementById("iotDevices").textContent = data.iot_devices;
    document.getElementById("findings").textContent = data.security_findings;

    const table = document.getElementById("deviceTable");
    table.innerHTML = "";

    if (devices.length === 0) {
        table.innerHTML = "<tr><td colspan='4'>No devices found</td></tr>";
        return;
    }

    devices.forEach((device, index) => {
        const ports = device.open_ports.length > 0 ? device.open_ports.join(", ") : "None";
        const row = document.createElement("tr");
        row.innerHTML =
            "<td>" + device.ip + "</td>" +
            "<td>" + device.device_type + "</td>" +
            "<td>" + ports + "</td>" +
            "<td><span class='risk " + device.risk + "'>" + device.risk + "</span></td>";
        row.onclick = () => showDetails(index);
        table.appendChild(row);
    });
}


function showDetails(index) {
    const device = devices[index];

    document.getElementById("dIp").textContent = device.ip;
    document.getElementById("dMac").textContent = device.mac;
    document.getElementById("dHostname").textContent = device.hostname;
    document.getElementById("dVendor").textContent = device.vendor;
    document.getElementById("dType").textContent = device.device_type;

    const portTable = document.getElementById("portTable");
    const list = document.getElementById("recommendations");
    portTable.innerHTML = "";
    list.innerHTML = "";

    if (device.findings.length === 0) {
        portTable.innerHTML = "<tr><td colspan='4'>No open ports found</td></tr>";
        list.innerHTML = "<li>No issues found on this device.</li>";
    }

    device.findings.forEach(f => {
        const row = document.createElement("tr");
        row.innerHTML =
            "<td>" + f.port + "</td>" +
            "<td>" + f.service + "</td>" +
            "<td><span class='risk " + f.risk + "'>" + f.risk + "</span></td>" +
            "<td>" + f.reason + "</td>";
        portTable.appendChild(row);

        const item = document.createElement("li");
        item.innerHTML = "<b>" + f.service + " (" + f.port + "):</b> " + f.recommendation;
        list.appendChild(item);
    });

    const box = document.getElementById("detailsBox");
    box.style.display = "block";
    box.scrollIntoView({ behavior: "smooth" });
}
