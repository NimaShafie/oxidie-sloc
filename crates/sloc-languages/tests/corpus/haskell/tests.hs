module MathSpec (spec) where

import Test.Hspec

spec :: Spec
spec = do
  describe "addition" $ do
    it "adds two numbers" $
      (1 + 1) `shouldBe` 2
    it "is commutative" $
      (2 + 3) `shouldBe` (3 + 2)
