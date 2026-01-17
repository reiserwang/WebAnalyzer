import JsonBlock from './core/JsonBlock.jsx';
import PortScan from './definitions/PortScan.jsx';
import MetasploitSuggester from './definitions/MetasploitSuggester.jsx';
import ActivePentest from './definitions/ActivePentest.jsx';
import IoTScanner from './definitions/IoTScanner.jsx';
import MSFDeepScan from './definitions/MSFDeepScan.jsx';
import VulnScanner from './definitions/VulnScanner.jsx';
import TopologyGraph from './definitions/TopologyGraph.jsx';

// Default renderer for modules without a specific definition
const DefaultRenderer = {
    component: JsonBlock
};

// List of all known modules. 
// Can be simple strings (using default renderer) or imported definitions.
const MODULE_DEFINITIONS = [
    "Domain Information",
    "DNS Records",
    "SEO Analysis",
    "Web Technologies",
    "Security Analysis",
    "Advanced Content Scan",
    "Contact Spy",
    "Subdomain Discovery",
    "Subdomain Takeover",
    PortScan, // Custom module
    "Nmap Zero Day Scan",
    "CloudFlare Bypass",
    "FRP Scanner",
    MetasploitSuggester,
    ActivePentest,
    IoTScanner,
    MSFDeepScan,
    VulnScanner,
    TopologyGraph
];

export const REGISTERED_MODULES = MODULE_DEFINITIONS.map(def => {
    if (typeof def === 'string') {
        return {
            id: def,
            name: def,
            component: DefaultRenderer.component
        };
    }
    return def;
});

export const getModuleRenderer = (id) => {
    const mod = REGISTERED_MODULES.find(m => m.id === id);
    return mod ? mod.component : DefaultRenderer.component;
};
