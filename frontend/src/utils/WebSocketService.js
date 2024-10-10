class WebSocketService {
    constructor(serverUrl) {
        this.serverUrl = serverUrl;
        this.socket = null;

    }

    connect() {

    }
    send(message) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(message);
        } else {
            console.error("WebSocket is not connected.");
        }
    }
    disconnect() {
        if (this.socket) {
            this.socket.close();
        }
    }

    ConnectEpollServer() {
        try {
            // Now that you have the IP, you might want to use it in your WebSocket URL
            // Assuming you intended to use the local IP dynamically but hardcoded for demonstration
            // const wsUrl = `ws://${ip}:12345`;
            const wsUrl = `ws://10.167.60.95:12345`; // Keeping your original hardcoded URL for reference
            console.log(`Attempting to connect WebSocket at ${wsUrl}`);
            this.serverUrl = wsUrl;
            this.socket = new WebSocket(this.serverUrl);


            this.socket.onopen = () => {
                console.log('WebSocket connected');
                const encoder = new TextEncoder(); // Use the TextEncoder to convert string to UTF-8 bytes
                const messageAsBytes = encoder.encode("WEB_SERVER");
                this.send(messageAsBytes);
            };
            this.socket.onerror = (error) => {
                console.error('WebSocket Error:', error);
            };
            this.socket.onmessage = (e) => {
                console.log('Received message:', e.data);
                // Handle incoming messages
            };
            this.socket.onclose = (e) => {
                console.log('WebSocket closed', e.reason);
            };
        } catch (error) {
            console.error("Error in WebSocket connection setup:", error);
        }
    }
}
export default WebSocketService;
