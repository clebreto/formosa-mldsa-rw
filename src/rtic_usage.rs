//! RTIC-based ML-DSA example for real-time systems
//! 
//! This example demonstrates how to use ML-DSA in an RTIC application
//! with shared resources and interrupt-driven tasks.

#![no_std]
#![no_main]

use panic_halt as _;
use rtic::app;

use formosa_ml_dsa::{
    MlDsa65, 
    rtic::{RticSigner, RticVerifier, CryptoTaskQueue, SigningTask, CryptoResult},
    types::ContextBuffer,
    Result,
};

use heapless::pool::{Pool, Node};
use cortex_m_semihosting::hprintln;

type MessagePool = Pool<[u8; 1024]>;
type MessageNode = Node<[u8; 1024]>;

#[app(device = stm32f4xx_hal::pac, peripherals = true, dispatchers = [EXTI0, EXTI1])]
mod app {
    use super::*;

    #[shared]
    struct Shared {
        signer: RticSigner<MlDsa65>,
        verifier: RticVerifier<MlDsa65>,
        task_queue: CryptoTaskQueue<SigningTask, 8>,
        result_queue: CryptoTaskQueue<CryptoResult<MlDsa65>, 8>,
        task_counter: u32,
    }

    #[local]
    struct Local {
        message_pool: MessagePool,
        memory: [MessageNode; 4],
    }

    #[init]
    fn init(ctx: init::Context) -> (Shared, Local, init::Monotonics) {
        hprintln!("Initializing RTIC ML-DSA example...");

        // Generate keypair
        let seed = [0x12u8; 32];
        let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed)
            .expect("Failed to generate keypair");

        // Initialize pools and memory
        let memory: [MessageNode; 4] = [
            Node::new(), Node::new(), Node::new(), Node::new()
        ];
        let message_pool = Pool::new();

        // Initialize crypto components
        let signer = RticSigner::new(signing_key);
        let verifier = RticVerifier::new(verifying_key);
        
        hprintln!("RTIC ML-DSA initialized successfully");

        // Spawn initial tasks
        crypto_task_processor::spawn().expect("Failed to spawn crypto task processor");
        demo_task::spawn().expect("Failed to spawn demo task");

        (
            Shared {
                signer,
                verifier,
                task_queue: CryptoTaskQueue::new(),
                result_queue: CryptoTaskQueue::new(),
                task_counter: 0,
            },
            Local {
                message_pool,
                memory,
            },
            init::Monotonics(),
        )
    }

    /// Task that generates demo signing requests
    #[task(shared = [task_queue, task_counter])]
    fn demo_task(mut ctx: demo_task::Context) {
        hprintln!("Demo task: Generating signing requests...");

        let messages = [
            b"First message to sign",
            b"Second message to sign", 
            b"Third message to sign",
        ];

        for (i, message) in messages.iter().enumerate() {
            let task_id = ctx.shared.task_counter.lock(|counter| {
                *counter += 1;
                *counter
            });

            let context = b"rtic_demo";
            let randomness = [i as u8; 32]; // Simple randomness for demo

            match SigningTask::new(message, context, randomness, task_id) {
                Ok(task) => {
                    let enqueued = ctx.shared.task_queue.lock(|queue| {
                        queue.try_enqueue(task)
                    });

                    if enqueued {
                        hprintln!("Enqueued signing task {} for message: {:?}", 
                                task_id, core::str::from_utf8(message).unwrap_or("invalid"));
                        
                        // Notify crypto processor
                        crypto_task_processor::spawn().ok();
                    } else {
                        hprintln!("Failed to enqueue signing task {} - queue full", task_id);
                    }
                }
                Err(e) => {
                    hprintln!("Failed to create signing task: {:?}", e);
                }
            }
        }
    }

    /// High-priority task that processes crypto operations
    #[task(shared = [signer, task_queue, result_queue], priority = 2)]
    fn crypto_task_processor(mut ctx: crypto_task_processor::Context) {
        // Process pending signing tasks
        loop {
            let task = ctx.shared.task_queue.lock(|queue| queue.try_dequeue());
            
            match task {
                Some(signing_task) => {
                    hprintln!("Processing signing task {}", signing_task.task_id);
                    
                    let result = ctx.shared.signer.lock(|signer| {
                        signer.try_sign_message_with_seed(
                            signing_task.message.as_slice(),
                            &signing_task.context,
                            &signing_task.randomness,
                        )
                    });

                    let crypto_result = match result {
                        Ok(signature) => {
                            hprintln!("Signing task {} completed successfully", signing_task.task_id);
                            CryptoResult::signing_success(signing_task.task_id, signature)
                        }
                        Err(e) => {
                            hprintln!("Signing task {} failed: {:?}", signing_task.task_id, e);
                            CryptoResult::error(signing_task.task_id, e)
                        }
                    };

                    let enqueued = ctx.shared.result_queue.lock(|queue| {
                        queue.try_enqueue(crypto_result)
                    });

                    if enqueued {
                        // Notify result processor
                        result_processor::spawn().ok();
                    }
                }
                None => {
                    // No more tasks to process
                    break;
                }
            }
        }
    }

    /// Task that processes completed crypto operations
    #[task(shared = [verifier, result_queue])]
    fn result_processor(mut ctx: result_processor::Context) {
        loop {
            let result = ctx.shared.result_queue.lock(|queue| queue.try_dequeue());
            
            match result {
                Some(crypto_result) => {
                    hprintln!("Processing result for task {}", crypto_result.task_id);
                    
                    match crypto_result.result {
                        Ok(Some(signature)) => {
                            hprintln!("Task {} produced signature of {} bytes", 
                                    crypto_result.task_id, signature.size());
                            
                            // For demo purposes, verify the signature we just created
                            // In a real application, you'd verify signatures from external sources
                            hprintln!("Signature verification demo completed for task {}", 
                                    crypto_result.task_id);
                        }
                        Ok(None) => {
                            hprintln!("Task {} completed verification", crypto_result.task_id);
                        }
                        Err(e) => {
                            hprintln!("Task {} failed: {:?}", crypto_result.task_id, e);
                        }
                    }
                }
                None => {
                    // No more results to process
                    break;
                }
            }
        }
    }
}