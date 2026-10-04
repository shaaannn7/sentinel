import type { AppProps } from 'next/app';
import Providers from '../src/components/Providers';
import '../src/styles/globals.css';

export default function App({ Component, pageProps }: AppProps) {
  return (
    <Providers>
      <Component {...pageProps} />
    </Providers>
  );
}