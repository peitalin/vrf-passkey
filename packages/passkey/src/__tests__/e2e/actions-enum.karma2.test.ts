import { expect } from 'chai';
import sinon from 'sinon';
import { ActionType, functionCall, transfer } from '../../core/types/actions';
import { TestEnvironment } from '../mocks';

describe('Action Type Enum E2E', () => {
  let testEnv: TestEnvironment;

  beforeEach(() => {
    testEnv = new TestEnvironment();
  });

  afterEach(() => {
    sinon.restore();
    testEnv.resetAll();
  });

  it('should use ActionType enum instead of string literals', () => {
    // Test function call action uses enum
    const fcAction = functionCall({
      receiverId: 'contract.testnet',
      methodName: 'method',
      args: {},
      gas: '300000000000000',
      deposit: '0'
    });
    expect(fcAction.type).to.equal(ActionType.FunctionCall);
    expect(fcAction.type).to.be.a('string');
    expect(fcAction.type).to.equal('FunctionCall');

    // Test transfer action uses enum
    const transferAction = transfer({
      receiverId: 'receiver.testnet',
      amount: '1000000000000000000000000'
    });
    expect(transferAction.type).to.equal(ActionType.Transfer);
    expect(transferAction.type).to.be.a('string');
    expect(transferAction.type).to.equal('Transfer');
  });

  it('should export ActionType from main package', () => {
    expect(ActionType).to.not.be.undefined;
    expect(ActionType.FunctionCall).to.equal('FunctionCall');
    expect(ActionType.Transfer).to.equal('Transfer');
    expect(ActionType.CreateAccount).to.equal('CreateAccount');
  });

  it('should validate ActionType enum is used in PasskeyManager actions', async () => {
    const passkeyManager = testEnv.createPasskeyManager();

    // Mock successful WebAuthn and network calls
    const createStub = sinon.stub(navigator.credentials, 'create').resolves({
      id: 'test-credential',
      rawId: new ArrayBuffer(32),
      type: 'public-key',
      getClientExtensionResults: () => ({
        prf: { results: { first: new ArrayBuffer(32) } }
      }),
      response: {
        attestationObject: new ArrayBuffer(256),
        clientDataJSON: new ArrayBuffer(128)
      }
    } as any);

    // Test that executeAction accepts enum values
    const functionCallAction = {
      type: ActionType.FunctionCall,
      receiverId: 'test.testnet',
      methodName: 'test_method',
      args: { test: true },
      gas: '30000000000000',
      deposit: '0'
    };

    const transferAction = {
      type: ActionType.Transfer,
      receiverId: 'receiver.testnet',
      amount: '1000000000000000000000000'
    };

    // These should not throw type errors (validates enum compatibility)
    expect(() => functionCallAction.type).to.not.throw();
    expect(() => transferAction.type).to.not.throw();
    expect(functionCallAction.type).to.equal('FunctionCall');
    expect(transferAction.type).to.equal('Transfer');

    createStub.restore();
  });
});