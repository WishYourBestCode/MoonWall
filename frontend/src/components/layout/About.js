import React, { useState } from "react";
import ip from "../ipInput";

function About() {
    const [TestSummary, setTestSummary] = useState('');
    const [errorMessage, setErrorMessage] = useState('');

    const fetchTestResult = async (event) => {
        event.preventDefault(); // Prevent the default anchor behavior

        try {
            const response = await fetch(`http://${ip}:12345`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: 'test' }),
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Error Response:', errorText);
                setErrorMessage(errorText);
            } else {
                const reader = response.body.getReader();
                const decoder = new TextDecoder("utf-8");
                let fullText = '';
                let done = false;

                while (!done) {
                    const { value, done: readerDone } = await reader.read();
                    if (value) {
                        const chunk = decoder.decode(value, { stream: !readerDone });
                        fullText += chunk;
                        console.log("Chunk received: ", chunk);  // Print each chunk as it arrives
                    }
                    done = readerDone;
                }

                setTestSummary(fullText);  // Store full result in the state after all chunks are received
                console.log("Full Data: ", fullText);
            }
        } catch (error) {
            console.error('Error:', error);
            setErrorMessage("An error occurred: " + error.message);
        }
    };

    return (
        <>
            <div className="section">
                <img src={require("../../assets/stars.png")} id="stars" />
                <a href="#" onClick={fetchTestResult}
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
                        TEST
                    </span>
                </a>
                <div>
                    <p>Test Summary:</p>
                    <pre>{TestSummary}</pre>
                    {errorMessage && <p style={{ color: 'red' }}>{errorMessage}</p>}
                </div>
            </div>
        </>
    );
}

export default About;
