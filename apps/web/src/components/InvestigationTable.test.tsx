import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import InvestigationTable from './InvestigationTable';

describe('InvestigationTable', () => {
  it('renders an empty state when there are no investigations', () => {
    render(<InvestigationTable investigations={[]} />);
    expect(screen.getByText('No investigations found')).toBeInTheDocument();
  });
});