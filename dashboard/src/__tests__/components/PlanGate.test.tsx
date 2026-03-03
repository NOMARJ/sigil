import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import PlanGate from '@/components/PlanGate'
import type { PlanTier } from '@/lib/types'

// Mock window.open for upgrade button tests
const mockWindowOpen = jest.fn()
Object.defineProperty(window, 'open', { value: mockWindowOpen })

describe('PlanGate Component', () => {
  beforeEach(() => {
    mockWindowOpen.mockClear()
  })

  describe('Access Control', () => {
    it('allows access for sufficient plan', () => {
      render(
        <PlanGate requiredPlan="pro" currentPlan="pro">
          <div data-testid="protected-content">Protected Content</div>
        </PlanGate>
      )

      expect(screen.getByTestId('protected-content')).toBeInTheDocument()
    })

    it('allows access for higher plan', () => {
      render(
        <PlanGate requiredPlan="pro" currentPlan="team">
          <div data-testid="protected-content">Protected Content</div>
        </PlanGate>
      )

      expect(screen.getByTestId('protected-content')).toBeInTheDocument()
    })

    it('blocks access for insufficient plan', () => {
      render(
        <PlanGate requiredPlan="pro" currentPlan="free">
          <div data-testid="protected-content">Protected Content</div>
        </PlanGate>
      )

      expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument()
    })
  })

  describe('Plan Hierarchy', () => {
    const testCases: Array<{
      required: PlanTier
      current: PlanTier
      shouldHaveAccess: boolean
    }> = [
      { required: 'free', current: 'free', shouldHaveAccess: true },
      { required: 'free', current: 'pro', shouldHaveAccess: true },
      { required: 'pro', current: 'free', shouldHaveAccess: false },
      { required: 'pro', current: 'pro', shouldHaveAccess: true },
      { required: 'pro', current: 'team', shouldHaveAccess: true },
      { required: 'team', current: 'pro', shouldHaveAccess: false },
      { required: 'team', current: 'team', shouldHaveAccess: true },
      { required: 'team', current: 'enterprise', shouldHaveAccess: true },
      { required: 'enterprise', current: 'team', shouldHaveAccess: false },
      { required: 'enterprise', current: 'enterprise', shouldHaveAccess: true },
    ]

    testCases.forEach(({ required, current, shouldHaveAccess }) => {
      it(`${shouldHaveAccess ? 'allows' : 'denies'} access for ${current} user accessing ${required} feature`, () => {
        render(
          <PlanGate requiredPlan={required} currentPlan={current}>
            <div data-testid="protected-content">Protected Content</div>
          </PlanGate>
        )

        if (shouldHaveAccess) {
          expect(screen.getByTestId('protected-content')).toBeInTheDocument()
        } else {
          expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument()
        }
      })
    })
  })

  describe('Upgrade Prompt', () => {
    it('shows upgrade prompt for blocked features', () => {
      render(
        <PlanGate requiredPlan="pro" currentPlan="free">
          <div data-testid="protected-content">Protected Content</div>
        </PlanGate>
      )

      expect(screen.getByText('Pro Plan Required')).toBeInTheDocument()
      expect(screen.getByText(/This feature requires a Pro plan or higher/)).toBeInTheDocument()
      expect(screen.getByText(/You're currently on the Free plan/)).toBeInTheDocument()
    })

    it('shows correct plan names in upgrade prompt', () => {
      render(
        <PlanGate requiredPlan="enterprise" currentPlan="team">
          <div data-testid="protected-content">Protected Content</div>
        </PlanGate>
      )

      expect(screen.getByText('Enterprise Plan Required')).toBeInTheDocument()
      expect(screen.getByText(/You're currently on the Team plan/)).toBeInTheDocument()
    })

    it('has working upgrade button', () => {
      render(
        <PlanGate requiredPlan="pro" currentPlan="free">
          <div data-testid="protected-content">Protected Content</div>
        </PlanGate>
      )

      const upgradeButton = screen.getByRole('button', { name: 'Upgrade Plan' })
      fireEvent.click(upgradeButton)

      expect(mockWindowOpen).toHaveBeenCalledWith('/settings#billing', '_self')
    })
  })

  describe('Custom Fallback', () => {
    it('renders custom fallback when provided', () => {
      const customFallback = <div data-testid="custom-fallback">Custom Upgrade Message</div>

      render(
        <PlanGate 
          requiredPlan="pro" 
          currentPlan="free" 
          fallback={customFallback}
        >
          <div data-testid="protected-content">Protected Content</div>
        </PlanGate>
      )

      expect(screen.getByTestId('custom-fallback')).toBeInTheDocument()
      expect(screen.getByText('Custom Upgrade Message')).toBeInTheDocument()
      expect(screen.queryByText('Pro Plan Required')).not.toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('has proper ARIA attributes', () => {
      render(
        <PlanGate requiredPlan="pro" currentPlan="free">
          <div data-testid="protected-content">Protected Content</div>
        </PlanGate>
      )

      const upgradeButton = screen.getByRole('button', { name: 'Upgrade Plan' })
      expect(upgradeButton).toBeInTheDocument()
      
      // The upgrade prompt should be clearly structured
      expect(screen.getByRole('heading', { level: 3 })).toHaveTextContent('Pro Plan Required')
    })

    it('provides clear messaging for screen readers', () => {
      render(
        <PlanGate requiredPlan="team" currentPlan="pro">
          <div data-testid="protected-content">Protected Content</div>
        </PlanGate>
      )

      // Should clearly communicate the requirement
      expect(screen.getByText(/This feature requires a Team plan or higher/)).toBeInTheDocument()
      expect(screen.getByText(/You're currently on the Pro plan/)).toBeInTheDocument()
    })
  })
})