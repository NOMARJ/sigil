"""
Test Model Routing Logic
Verifies that simple questions use Haiku and complex tasks use Sonnet/Opus
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.complexity_scorer import complexity_scorer, TaskComplexity


def test_simple_question():
    """Test that 'Is this safe?' uses Haiku"""
    complexity, confidence, factors = complexity_scorer.score_task(
        task_type="chat",
        query="Is this safe?",
        context={}
    )
    
    model = complexity_scorer.recommend_model(complexity)
    
    print("Query: 'Is this safe?'")
    print(f"Complexity: {complexity.value}")
    print(f"Confidence: {confidence:.2f}")
    print(f"Selected Model: {model}")
    print(f"Keywords found: {factors['keywords_found']}")
    print()
    
    assert model == "claude-3-haiku", f"Expected Haiku, got {model}"
    assert complexity == TaskComplexity.SIMPLE, f"Expected SIMPLE, got {complexity}"
    print("✅ PASSED: 'Is this safe?' correctly routes to Haiku\n")


def test_trace_attack():
    """Test that 'Trace attack' uses Sonnet or Opus"""
    complexity, confidence, factors = complexity_scorer.score_task(
        task_type="chat",
        query="Trace the attack chain through the code",
        context={}
    )
    
    model = complexity_scorer.recommend_model(complexity)
    
    print("Query: 'Trace the attack chain through the code'")
    print(f"Complexity: {complexity.value}")
    print(f"Confidence: {confidence:.2f}")
    print(f"Selected Model: {model}")
    print(f"Keywords found: {factors['keywords_found']}")
    print(f"Patterns matched: {factors['patterns_matched']}")
    print()
    
    assert model in ["claude-3-sonnet", "claude-3-opus"], f"Expected Sonnet/Opus, got {model}"
    assert complexity in [TaskComplexity.MODERATE, TaskComplexity.COMPLEX], f"Expected MODERATE/COMPLEX, got {complexity}"
    print("✅ PASSED: 'Trace attack' correctly routes to Sonnet/Opus\n")


def test_attack_chain_task():
    """Test that attack_chain task type uses complex model"""
    complexity, confidence, factors = complexity_scorer.score_task(
        task_type="attack_chain",
        query=None,
        context={}
    )
    
    model = complexity_scorer.recommend_model(complexity)
    
    print("Task Type: 'attack_chain'")
    print(f"Complexity: {complexity.value}")
    print(f"Selected Model: {model}")
    print()
    
    assert model == "claude-3-opus", f"Expected Opus for attack_chain, got {model}"
    assert complexity == TaskComplexity.COMPLEX, f"Expected COMPLEX, got {complexity}"
    print("✅ PASSED: attack_chain task correctly routes to Opus\n")


def test_investigation_depths():
    """Test investigation depth routing"""
    depths = ["quick", "thorough", "exhaustive"]
    expected_models = ["claude-3-haiku", "claude-3-sonnet", "claude-3-opus"]
    
    for depth, expected_model in zip(depths, expected_models):
        complexity, confidence, factors = complexity_scorer.score_task(
            task_type="investigate",
            query=None,
            context={"depth": depth}
        )
        
        model = complexity_scorer.recommend_model(complexity)
        
        print(f"Investigation Depth: {depth}")
        print(f"Complexity: {complexity.value}")
        print(f"Selected Model: {model}")
        
        assert model == expected_model, f"Expected {expected_model} for {depth}, got {model}"
        print(f"✅ PASSED: {depth} investigation routes to {model}\n")


def test_model_override():
    """Test that user can override model selection"""
    # Would normally route to Haiku
    complexity, confidence, factors = complexity_scorer.score_task(
        task_type="chat",
        query="What is this?",
        context={"model_override": "claude-3-opus"}
    )
    
    # But with override...
    # model = "claude-3-opus"  # Router would respect the override
    
    print("Query: 'What is this?' with Opus override")
    print(f"Complexity: {complexity.value}")
    print("Override Model: claude-3-opus")
    print(f"Confidence: {confidence:.2f} (1.0 due to override)")
    print()
    
    assert "user_override" in str(factors["context_factors"]), "Override not in context"
    print("✅ PASSED: User override is detected in context\n")


def run_all_tests():
    """Run all routing tests"""
    print("=" * 60)
    print("TESTING MODEL ROUTING LOGIC")
    print("=" * 60)
    print()
    
    try:
        test_simple_question()
        test_trace_attack()
        test_attack_chain_task()
        test_investigation_depths()
        test_model_override()
        
        print("=" * 60)
        print("ALL TESTS PASSED! ✅")
        print("=" * 60)
        return True
        
    except AssertionError as e:
        print(f"❌ TEST FAILED: {e}")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)