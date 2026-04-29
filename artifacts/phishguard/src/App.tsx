import { Switch, Route, Router as WouterRouter } from "wouter";
import { Home } from "./pages/Home";
import { Website } from "./pages/Website";
import { Message } from "./pages/Message";
import { Email } from "./pages/Email";
import { NotFound } from "./pages/not-found";

function App() {
  return (
    <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
      <Switch>
        <Route path="/" component={Home} />
        <Route path="/website" component={Website} />
        <Route path="/message" component={Message} />
        <Route path="/email" component={Email} />
        <Route component={NotFound} />
      </Switch>
    </WouterRouter>
  );
}

export default App;
