import logo from './logo.svg';
import './App.css';
import 'reset-css';
import Navbar from "./components/Navbar";
import Home from './components/layout/Home';
import {BrowserRouter, Route, Routes} from "react-router-dom";
import React, {useEffect} from "react";
import Moonwall from "./components/layout/Moonwall";
import About from "./components/layout/About";
import Moonlog from "./components/layout/Moonlog";
import Moondoc from "./components/layout/Moondoc";

function App() {
  useEffect(() => {
    console.log("main");
  }, []);
  return (
      <>
        <BrowserRouter basename=''>
          <Navbar></Navbar>
          <Routes>
            <Route index element={<Home/>}></Route>
              <Route path="moondoc" element={<Moondoc/>}>Document</Route>
              <Route path="moonwall" element={<Moonwall/>}>Moonwall</Route>
              <Route path="moonlog" element={<Moonlog/>}>Moonlog</Route>
              <Route path="about" element={<About/>}></Route>
          </Routes>
        </BrowserRouter>
      </>
  );
}

export default App;
