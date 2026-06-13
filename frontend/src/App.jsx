import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import InvestigatorPage from "./pages/InvestigatorPage";
import EvaluationPage from "./pages/EvaluationPage";

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/investigator" element={<InvestigatorPage />} />
        <Route path="/evaluation" element={<EvaluationPage />} />
      </Routes>
    </Router>
  );
}