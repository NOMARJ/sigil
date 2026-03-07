import { NextRequest, NextResponse } from 'next/server';

interface CheckoutRequest {
  tier: 'free' | 'pro' | 'enterprise';
  billing_cycle: 'monthly' | 'yearly';
  success_url: string;
  cancel_url: string;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body: CheckoutRequest = await request.json();
    const { tier, billing_cycle, success_url, cancel_url } = body;

    // Validate input
    if (!tier || !billing_cycle || !success_url || !cancel_url) {
      return NextResponse.json(
        { error: 'Missing required fields' },
        { status: 400 }
      );
    }

    if (tier === 'free') {
      return NextResponse.json(
        { error: 'Free tier does not require checkout' },
        { status: 400 }
      );
    }

    if (tier === 'enterprise') {
      return NextResponse.json(
        { error: 'Enterprise tier requires custom pricing' },
        { status: 400 }
      );
    }

    // For now, return a mock Stripe checkout URL
    // In production, this would integrate with actual Stripe API
    const mockCheckoutUrl = `https://checkout.stripe.com/pay/cs_test_${tier}_${billing_cycle}_${Date.now()}`;

    // TODO: Replace with actual Stripe integration
    // const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
    // const session = await stripe.checkout.sessions.create({
    //   mode: 'subscription',
    //   payment_method_types: ['card'],
    //   line_items: [
    //     {
    //       price: billing_cycle === 'yearly' ? 'price_yearly_pro' : 'price_monthly_pro',
    //       quantity: 1,
    //     },
    //   ],
    //   success_url,
    //   cancel_url,
    //   metadata: {
    //     tier,
    //     billing_cycle,
    //   },
    // });

    return NextResponse.json({
      checkout_url: mockCheckoutUrl,
      session_id: `cs_test_${tier}_${billing_cycle}_${Date.now()}`,
    });

  } catch (error) {
    console.error('Checkout error:', error);
    return NextResponse.json(
      { error: 'Failed to create checkout session' },
      { status: 500 }
    );
  }
}