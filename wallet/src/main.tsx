import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import './index.css'
import Wallet from './Wallet.tsx'
import Explorer from './Explorer.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter basename="/">
      <Routes>
        <Route path="/wallet/*" element={<Wallet />} />
        <Route path="/explorer/*" element={<Explorer />} />
        <Route path="/" element={<Navigate to="/explorer" replace />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
