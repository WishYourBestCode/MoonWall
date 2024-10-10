import Moonlog from './Moonlog'; // Import the Moonlog component
import React, { useState } from "react";
import Form from "react-bootstrap/Form";
import { Button } from "react-bootstrap";
import ip from "../ipInput"
const ParentMoonWall = () => {
    const [responseQuery, setResponseQuery] = useState([]);   // State for firewall query result
    const [formData, setFormData] = useState({
        firewallQuery: ''
    });

    const handleSubmit = async (e) => {
        e.preventDefault();
        console.log(formData.firewallQuery + ' : TEST-123');
        try {
            const response = await fetch(`http://${ip}:12345`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: formData.firewallQuery }),
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Error Response:', errorText);
            } else {
                const reader = response.body.getReader();
                let chunks = [];  // Store received chunks
                let done = false;

                while (!done) {
                    const { done: readerDone, value } = await reader.read();
                    if (value) {
                        chunks.push(new TextDecoder().decode(value));
                    }
                    done = readerDone;
                }
                const fullResponse = chunks.join('');
                const data = JSON.parse(fullResponse);
                const formattedData = data.message
                    .split(/(?=iptables)/g)
                    .map(str => str.trim())
                    .filter(Boolean);

                setResponseQuery(formattedData);

            }
        } catch (error) {
            console.error('Error:', error);
        }
    };

    const handleInputChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    return (
        <div className="parent-grid">
            {/* First Row: Form and Response Container */}
            <div className="form-and-response">
                <Form onSubmit={handleSubmit}>
                    <div className="d-grid gap-2">
                        <Form.Group className="mb-3" controlId="formRequest.TextArea">
                            <Form.Label className="textLabel">Insert MoonWall Rules</Form.Label>
                            <Form.Control
                                as="textarea"
                                rows={3}
                                name="firewallQuery"
                                value={formData.firewallQuery}
                                onChange={handleInputChange}
                            />
                        </Form.Group>

                        <Button variant="secondary" type="submit">
                            Create Firewall
                        </Button>
                    </div>
                </Form>

                <div className={`response-container ${responseQuery ? 'visible' : ''}`}>
                    <div className="response-text">
                        <ul>
                            {responseQuery.map((command, index) => (
                                <li key={index}>{command}</li>  // Display each command in a list item
                            ))}
                        </ul>
                    </div>
                </div>
            </div>


        </div>
    );
};

export default ParentMoonWall;
