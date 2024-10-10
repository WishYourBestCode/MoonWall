import "./styles/style.css";
import "./styles/section.css";


import React, {useState, useEffect} from "react";
import { NavLink } from 'react-router-dom'



function Navbar(){

    return(
        <>
            <div className="navbar">
                <a href="#" className="logo">MoonW</a>
                <ul>
                    <li className="nav_item">
                        <NavLink className="nav_item_link" to="/">Home</NavLink>
                    </li>
                    <li className="nav_item">
                        <NavLink className="nav_item_link" to="/moondoc">Manual</NavLink>
                    </li>
                    <li className="nav_item">
                        <NavLink className="nav_item_link" to="/moonwall">MoonWall</NavLink>
                    </li>
                    <li className="nav_item">
                        <NavLink className="nav_item_link" to="/moonlog">MoonLog</NavLink>
                    </li>
                    <li className="nav_item">
                        <NavLink className="nav_item_link" to="/about">About</NavLink>
                    </li>
                </ul>
            </div>
        </>
    )
}


export default Navbar

