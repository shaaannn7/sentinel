import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import SafeEmailBody from './SafeEmailBody';

describe('SafeEmailBody', () => {
  it('strips dangerous script tags from html content', () => {
    const maliciousHtml = '<p>Normal content</p><script>alert("xss")</script>';
    const { container } = render(
      <SafeEmailBody htmlBody={maliciousHtml} plainBody="Normal content" />
    );

    // Script tags should not exist in the DOM
    expect(container.querySelector('script')).toBeNull();
    expect(screen.getByText('Normal content')).toBeInTheDocument();
  });

  it('strips dangerous onerror handlers and javascript: URLs', () => {
    const maliciousHtml = '<img src="x" onerror="alert(1)" /><a href="javascript:alert(2)">Malicious Link</a>';
    const { container } = render(
      <SafeEmailBody htmlBody={maliciousHtml} plainBody="Fallback" />
    );

    const img = container.querySelector('img');
    if (img) {
      expect(img.getAttribute('onerror')).toBeNull();
    }

    const link = container.querySelector('a');
    if (link) {
      const href = link.getAttribute('href');
      // If href is stripped it is null, otherwise it must not contain javascript:
      expect(href === null || !href.includes('javascript:')).toBe(true);
    }
  });

  it('allows toggling between Sanitized HTML and Plain Text view', () => {
    render(
      <SafeEmailBody
        htmlBody="<strong>Formatted HTML</strong>"
        plainBody="Raw plain body text"
      />
    );

    // Default is Sanitized HTML
    expect(screen.getByText('Formatted HTML')).toBeInTheDocument();

    // Toggle to Plain Text
    const plainTextBtn = screen.getByRole('button', { name: /plain text/i });
    fireEvent.click(plainTextBtn);

    expect(screen.getByText('Raw plain body text')).toBeInTheDocument();
  });

  it('renders empty fallback when neither htmlBody nor plainBody is provided', () => {
    render(<SafeEmailBody />);
    expect(screen.getByText(/no body content available/i)).toBeInTheDocument();
  });
});
