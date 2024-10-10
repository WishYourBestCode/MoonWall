import React, {useState} from "react";
import { useLocation } from "react-router-dom";
import '../styles/layout/moondoc.css';
import ip from "../ipInput";

function Moondoc() {
    const location = useLocation();
    const [responseQuery, setResponseQuery] = useState("");
    const [instructions, setInstructions] = useState({});



    const formatKey = (key) => {
        return key.replace(/_/g, ' ').replace(/(?<=^[A-Za-z])\s/, '. ');
    };
    const handleExploreClick = async (event) => {
        event.preventDefault(); // Prevent the default anchor behavior

        try {
            const response = await fetch(`http://${ip}:12345`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Error Response:', errorText);
            } else {
                const data = await response.json();
                setResponseQuery(data.message);
                console.log("My Data =====>" + data.message);
                // Set the fetched message into state
                setInstructions(data.message);
                const moon = document.getElementById('moon');
                if (moon) {
                    moon.style.opacity = '0';
                }
            }
        } catch (error) {
            console.error('Error:', error);
        }
    };
    // Access the message key, assuming the server sends it in { message: { ... } } structure
    const renderContent = (data) => {
        return Object.keys(data).map(key => {
            const formattedKey = formatKey(key);
            const value = data[key];
            if (typeof value === 'object' && !Array.isArray(value)) {
                return (
                    <div key={key}>
                        <h2 style={{ fontSize: '15px', color: '#0074E8', fontWeight: '900' }}>{formattedKey}</h2>
                        <div style={{ marginLeft: '5px' }}>
                            {renderContent(value)}
                        </div>
                    </div>
                );
            } else if (Array.isArray(value)) {
                return (
                    <div key={key}>
                        <h2 style={{ fontSize: '15px', color: '#0074E8', fontWeight: '900' }}>{formattedKey}</h2>
                        <ul>
                            {value.map((item, index) => (
                                <li key={index} style={{ fontSize: '14px', color: 'white', fontWeight: '500' }}>{item}</li>
                            ))}
                        </ul>
                    </div>
                );
            } else {
                return (
                    <div key={key}>
                        <p style={{ fontSize: '14px', color: 'white', fontWeight: '500'}}>
                            <strong>{key.replace(/_/g, ' ')}:</strong> {value}
                        </p>
                    </div>
                );
            }
        });
    };
    return (
        <>
            <div className="section">
                <img src={require("../../assets/stars.png")} id="stars" alt="stars"/>
                <a href="#" onClick={handleExploreClick}
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
                MoonDoc
                    </span>
                </a>
                <div id="instructions">
                    {renderContent(instructions)}
                </div>
            </div>
        </>
    );
}

export default Moondoc;
