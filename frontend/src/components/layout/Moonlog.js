import React, { useState } from "react";
import '../styles/layout/moonlog.css';
import Table from 'react-bootstrap/Table';
import ip from '../ipInput'

function Moonlog() {
    const [iptablesData, setIptablesData] = useState({});
    const [errorMessage, setErrorMessage] = useState('');

    // Function to fetch iptables data from the server
    const fetchIptablesData = async () => {
        try {
            const additionalResponse = await fetch(`http://${ip}:12345`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: 'table' }),
            });
            if (additionalResponse.ok) {
                // Step 1: Fetch response body as a readable stream
                const reader = additionalResponse.body.getReader();
                let chunks = [];  // Store received chunks
                let done = false;

                // Step 2: Read data from the stream
                while (!done) {
                    const { done: readerDone, value } = await reader.read();
                    if (value) {
                        // Concatenate each chunk into chunks array
                        chunks.push(new TextDecoder().decode(value));
                    }
                    done = readerDone;
                }

                // Step 3: Combine all chunks into a single string
                const fullResponse = chunks.join('');
                const parsedResponse = JSON.parse(fullResponse);
                console.log("Full Response:", parsedResponse);

                // Step 4: Parse the `message` field in the response if nested
                const iptablesDataResponse = JSON.parse(parsedResponse.message);

                console.log("Parsed iptablesDataResponse:", iptablesDataResponse);

                // Process the data: replace the first entry with empty spaces if it matches the column headers
                const processedData = {};
                Object.keys(iptablesDataResponse).forEach((key) => {
                    const section = iptablesDataResponse[key];

                    // Safely check if columns and entries exist and ensure they're arrays
                    const columns = Array.isArray(section.columns) ? section.columns : [];
                    const entries = Array.isArray(section.entries) ? section.entries : [];

                    // Remove the first entry if it matches the column headers or is empty
                    const modifiedEntries = entries.length > 0
                        ? entries.slice(1) // Skip the first entry (which matches the column headers)
                        : [Array(columns.length).fill(' ').join(' ')]; // Ensure at least one empty row

                    processedData[key] = {
                        columns,
                        entries: modifiedEntries
                    };
                });

                setIptablesData(processedData);
                setErrorMessage(''); // Clear any previous errors
            } else {
                console.error('Failed to fetch iptables information');
                setErrorMessage('Failed to fetch iptables information');
            }
        } catch (error) {
            console.error('Error fetching data:', error);
            setErrorMessage('Error fetching iptables data');
        }
    };


    const renderTable = (title, data) => (
        <div key={title}>
            <h4>{title}</h4>
            <Table striped bordered hover size="sm">
                <thead>
                <tr>
                    {data.columns.map((column, index) => (
                        <th key={index}>{column}</th>
                    ))}
                </tr>
                </thead>
                <tbody>
                {data.entries.length > 0 ? (
                    data.entries.map((entry, rowIndex) => (
                        <tr key={rowIndex}>
                            {entry.split(/\s+/).map((cell, cellIndex) => (
                                <td key={cellIndex}>{cell || ' '}</td>
                            ))}
                        </tr>
                    ))
                ) : (
                    <tr>
                        <td colSpan={data.columns.length}>No entries available</td>
                    </tr>
                )}
                </tbody>
            </Table>
        </div>
    );

    return (
        <>
            <div className="section">
                <img src={require("../../assets/stars.png")} id="stars" alt="stars"/>
                <a href="#" onClick={fetchIptablesData}
                   style={{
                       display: 'block', // Ensure block display for clickable area
                       position: 'absolute',
                       width: '500px', // Match image width
                       height: '500px', // Set the height explicitly to match the image size
                       cursor: 'pointer', // Show pointer cursor to indicate clickable element
                       top: '-20px',
                   }}>
                    <img
                        style={{
                            width: '500px', // Match image width
                            height: '500px', // Explicit height for image
                            display: 'block', // Block display ensures proper sizing
                            zIndex: '10', // Set z-index to ensure it's interactive
                            pointerEvents: 'auto',
                            mixBlendMode: 'screen',
                        }}
                        src={require("../../assets/moon.png")} alt="moon"
                    />

                    <span
                        style={{
                            position: 'absolute',
                            background: 'linear-gradient(to right, black, white)', // Gradient background from black to white
                            WebkitBackgroundClip: 'text', // Clip background to text
                            WebkitTextFillColor: 'transparent',
                            opacity: '1',
                            fontSize: '24px',
                            fontWeight: 'bold',
                            top: '50%',
                            left: '50%',
                            transform: 'translate(-50%, -400%)',
                            zIndex: '11',
                            pointerEvents: 'none',

                        }}
                    >
        MoonLog
    </span>
                </a>

                {errorMessage && <p className="error">{errorMessage}</p>}

                <div className="logResult">
                    {Object.keys(iptablesData).length > 0 ? (
                        Object.keys(iptablesData).map((key) =>
                            renderTable(key, iptablesData[key])
                        )
                    ) : (
                        <></>
                    )}
                </div>
            </div>
        </>
    );
}

export default Moonlog;
