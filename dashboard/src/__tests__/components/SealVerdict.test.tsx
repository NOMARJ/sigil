import React from 'react'
import { render, screen } from '@testing-library/react'
import '@testing-library/jest-dom'
import SealVerdict, { scoreToVerdict } from '@/components/SealVerdict'

describe('SealVerdict component', () => {
  describe('Verdict variants', () => {
    it('renders the clean Seal SVG and label', () => {
      const { container } = render(<SealVerdict verdict="clean" />)
      const img = container.querySelector('img')
      expect(img?.getAttribute('src')).toBe('/brand/seal/sigil-seal-clean.svg')
      expect(screen.getByText('CLEAN')).toBeInTheDocument()
    })

    it('renders the low-risk Seal SVG and label', () => {
      const { container } = render(<SealVerdict verdict="low" />)
      expect(container.querySelector('img')?.getAttribute('src')).toBe(
        '/brand/seal/sigil-seal-low.svg',
      )
      expect(screen.getByText('LOW RISK')).toBeInTheDocument()
    })

    it('renders the medium-risk Seal SVG and label', () => {
      const { container } = render(<SealVerdict verdict="medium" />)
      expect(container.querySelector('img')?.getAttribute('src')).toBe(
        '/brand/seal/sigil-seal-medium.svg',
      )
      expect(screen.getByText('MEDIUM RISK')).toBeInTheDocument()
    })

    it('renders the high-risk Seal SVG and label', () => {
      const { container } = render(<SealVerdict verdict="high" />)
      expect(container.querySelector('img')?.getAttribute('src')).toBe(
        '/brand/seal/sigil-seal-high.svg',
      )
      expect(screen.getByText('HIGH RISK')).toBeInTheDocument()
    })

    it('renders the critical Seal SVG and label', () => {
      const { container } = render(<SealVerdict verdict="critical" />)
      expect(container.querySelector('img')?.getAttribute('src')).toBe(
        '/brand/seal/sigil-seal-critical.svg',
      )
      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    })
  })

  describe('Small-size variant (directive §1)', () => {
    it('switches to sigil-seal-small.svg at size="sm" regardless of verdict', () => {
      const verdicts: Array<'clean' | 'low' | 'medium' | 'high' | 'critical'> = [
        'clean',
        'low',
        'medium',
        'high',
        'critical',
      ]
      for (const v of verdicts) {
        const { container, unmount } = render(<SealVerdict verdict={v} size="sm" />)
        expect(container.querySelector('img')?.getAttribute('src')).toBe(
          '/brand/seal/sigil-seal-small.svg',
        )
        unmount()
      }
    })
  })

  describe('Strict-liability label rules (directive §4)', () => {
    it('clean verdict with 8 phases passed shows attestation phrasing — never "Safe to install"', () => {
      render(<SealVerdict verdict="clean" phasesPassed={8} />)
      expect(screen.getByText('8/8 phases passed')).toBeInTheDocument()
      expect(screen.queryByText(/safe to install/i)).not.toBeInTheDocument()
      expect(screen.queryByText(/verified safe/i)).not.toBeInTheDocument()
    })

    it('clean verdict without phasesPassed shows "no findings detected"', () => {
      render(<SealVerdict verdict="clean" />)
      expect(screen.getByText(/no findings detected/i)).toBeInTheDocument()
    })

    it('renders score subtext when score prop is provided', () => {
      render(<SealVerdict verdict="high" score={37} />)
      expect(screen.getByText(/score 37/i)).toBeInTheDocument()
    })
  })

  describe('Label pairing (directive §3 — never colour alone)', () => {
    it('always renders a text label by default', () => {
      const { container } = render(<SealVerdict verdict="critical" />)
      // Image plus a label span
      expect(container.querySelector('img')).toBeInTheDocument()
      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    })

    it('hides the label only when showLabel is explicitly false', () => {
      render(<SealVerdict verdict="critical" showLabel={false} />)
      expect(screen.queryByText('CRITICAL')).not.toBeInTheDocument()
    })
  })
})

describe('scoreToVerdict mapping (directive §3)', () => {
  const cases: Array<[number, ReturnType<typeof scoreToVerdict>]> = [
    [0, 'clean'],
    [1, 'low'],
    [9, 'low'],
    [10, 'medium'],
    [24, 'medium'],
    [25, 'high'],
    [49, 'high'],
    [50, 'critical'],
    [100, 'critical'],
  ]
  for (const [score, expected] of cases) {
    it(`maps score ${score} to ${expected}`, () => {
      expect(scoreToVerdict(score)).toBe(expected)
    })
  }
})
