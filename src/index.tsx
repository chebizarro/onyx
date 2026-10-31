import { render } from 'solid-js/web';
import './lib/vault/engine';
import App from './App';
import './styles.css';

const root = document.getElementById('root');

if (root) {
  render(() => <App />, root);
}
