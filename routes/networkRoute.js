
import express from "express"
// import ipscanController from "../controller/networkController.js"

// router.get("/" , ipscanController)
import {
    dnsScan,
    firewallTest,
    ipScan,
    portScan,
    protocolScan,
    serviceDetect,
    subnetScan,
    latencyTest
} from "../controller/networkController.js"

const router = express.Router();

// DNS Hostname Scanning
router.get("/dns/", dnsScan)

// Firewall and ACL Testing
router.get("/firewall", firewallTest)

// IP Scanning
router.get("/ipscan", ipScan)

// Port Scanning
router.get("/portscan", portScan)

// Protocol Analysis
router.get("/protocol", protocolScan)

// Service Detection
router.get("/services", serviceDetect)

// Subnet and VLAN Scanning
router.get("/subnet", subnetScan)

// Network Latency Testing
router.get("/latency", latencyTest)

export default router