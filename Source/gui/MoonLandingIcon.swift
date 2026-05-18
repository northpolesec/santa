/// Copyright 2026 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

import SwiftUI

// Moon draws a gray sphere with a few craters.
private struct Moon: View {
  var body: some View {
    Circle()
      .fill(
        RadialGradient(
          colors: [Color(white: 0.92), Color(white: 0.55)],
          center: UnitPoint(x: 0.35, y: 0.35),
          startRadius: 1,
          endRadius: 16
        )
      )
      .overlay(
        ZStack {
          Circle().fill(Color(white: 0.4).opacity(0.5)).frame(width: 5, height: 5)
            .offset(x: -6, y: 3)
          Circle().fill(Color(white: 0.4).opacity(0.5)).frame(width: 3, height: 3)
            .offset(x: 5, y: 6)
          Circle().fill(Color(white: 0.4).opacity(0.5)).frame(width: 2, height: 2)
            .offset(x: 2, y: -7)
          Circle().fill(Color(white: 0.4).opacity(0.5)).frame(width: 2, height: 2)
            .offset(x: -3, y: -4)
        }
      )
  }
}

// LunarLander draws a small Apollo LM silhouette: antenna, hexagonal ascent
// stage, wider octagonal descent stage with central engine bell, and four
// splayed legs ending in circular foot pads.
private struct LunarLander: View {
  var body: some View {
    Canvas { ctx, size in
      let w = size.width
      let h = size.height
      let bodyFill = Color(white: 0.78)
      let bodyShadow = Color(white: 0.48)
      let outline = Color(white: 0.25)
      let padFill = Color(white: 0.6)

      var antenna = Path()
      antenna.move(to: CGPoint(x: w * 0.5, y: h * 0.02))
      antenna.addLine(to: CGPoint(x: w * 0.5, y: h * 0.18))
      ctx.stroke(antenna, with: .color(outline), lineWidth: 0.7)

      var ascent = Path()
      ascent.move(to: CGPoint(x: w * 0.32, y: h * 0.18))
      ascent.addLine(to: CGPoint(x: w * 0.68, y: h * 0.18))
      ascent.addLine(to: CGPoint(x: w * 0.78, y: h * 0.30))
      ascent.addLine(to: CGPoint(x: w * 0.78, y: h * 0.48))
      ascent.addLine(to: CGPoint(x: w * 0.22, y: h * 0.48))
      ascent.addLine(to: CGPoint(x: w * 0.22, y: h * 0.30))
      ascent.closeSubpath()
      ctx.fill(ascent, with: .color(bodyFill))
      ctx.stroke(ascent, with: .color(outline), lineWidth: 0.5)

      var descent = Path()
      descent.move(to: CGPoint(x: w * 0.15, y: h * 0.48))
      descent.addLine(to: CGPoint(x: w * 0.85, y: h * 0.48))
      descent.addLine(to: CGPoint(x: w * 0.92, y: h * 0.55))
      descent.addLine(to: CGPoint(x: w * 0.92, y: h * 0.70))
      descent.addLine(to: CGPoint(x: w * 0.85, y: h * 0.78))
      descent.addLine(to: CGPoint(x: w * 0.15, y: h * 0.78))
      descent.addLine(to: CGPoint(x: w * 0.08, y: h * 0.70))
      descent.addLine(to: CGPoint(x: w * 0.08, y: h * 0.55))
      descent.closeSubpath()
      ctx.fill(descent, with: .color(bodyShadow))
      ctx.stroke(descent, with: .color(outline), lineWidth: 0.5)

      var bell = Path()
      bell.move(to: CGPoint(x: w * 0.42, y: h * 0.78))
      bell.addLine(to: CGPoint(x: w * 0.58, y: h * 0.78))
      bell.addLine(to: CGPoint(x: w * 0.54, y: h * 0.86))
      bell.addLine(to: CGPoint(x: w * 0.46, y: h * 0.86))
      bell.closeSubpath()
      ctx.fill(bell, with: .color(outline))

      var legs = Path()
      legs.move(to: CGPoint(x: w * 0.20, y: h * 0.65))
      legs.addLine(to: CGPoint(x: w * 0.02, y: h * 0.95))
      legs.move(to: CGPoint(x: w * 0.42, y: h * 0.78))
      legs.addLine(to: CGPoint(x: w * 0.32, y: h * 0.95))
      legs.move(to: CGPoint(x: w * 0.58, y: h * 0.78))
      legs.addLine(to: CGPoint(x: w * 0.68, y: h * 0.95))
      legs.move(to: CGPoint(x: w * 0.80, y: h * 0.65))
      legs.addLine(to: CGPoint(x: w * 0.98, y: h * 0.95))
      ctx.stroke(legs, with: .color(outline), lineWidth: 0.8)

      let padR: CGFloat = 1.4
      for cx: CGFloat in [0.02, 0.32, 0.68, 0.98] {
        let center = CGPoint(x: w * cx, y: h * 0.95)
        let rect = CGRect(
          x: center.x - padR,
          y: center.y - padR,
          width: padR * 2,
          height: padR * 2
        )
        ctx.fill(Path(ellipseIn: rect), with: .color(padFill))
        ctx.stroke(Path(ellipseIn: rect), with: .color(outline), lineWidth: 0.4)
      }
    }
    .frame(width: 18, height: 18)
  }
}

// MoonLandingIcon plays a one-shot sequence in place of the header icon: spin
// the logo, crossfade to a moon, then descend an Apollo lander onto it.
// Clicking the icon replays the sequence.
struct MoonLandingIcon: View {
  @State private var rotation: Double = 0
  @State private var showMoon: Bool = false
  @State private var landerY: CGFloat = -50

  var body: some View {
    ZStack {
      Image(nsImage: NSImage(named: "MessageIcon") ?? NSImage())
        .resizable()
        .scaledToFill()
        .frame(width: 32, height: 32)
        .saturation(0.9)
        .rotationEffect(.degrees(rotation))
        .scaleEffect(showMoon ? 0.1 : 1)
        .opacity(showMoon ? 0 : 1)

      Moon()
        .frame(width: 28, height: 28)
        .scaleEffect(showMoon ? 1 : 0.1)
        .opacity(showMoon ? 1 : 0)

      LunarLander()
        .offset(y: landerY)
        .opacity(showMoon ? 1 : 0)
    }
    .frame(width: 32, height: 32)
    .help("Anniversary of the Apollo 11 moon landing")
    .contentShape(Rectangle())
    .onTapGesture {
      Task { await runSequence(initialDelayNanos: 100_000_000) }
    }
    .task {
      await runSequence(initialDelayNanos: 400_000_000)
    }
  }

  private func runSequence(initialDelayNanos: UInt64) async {
    // Snap state back to the start without animating, so a replay doesn't
    // unwind the rotation or float the lander back up.
    var reset = Transaction()
    reset.disablesAnimations = true
    withTransaction(reset) {
      rotation = 0
      showMoon = false
      landerY = -50
    }

    try? await Task.sleep(nanoseconds: initialDelayNanos)
    withAnimation(.linear(duration: 2.5)) {
      rotation = 1440
    }
    try? await Task.sleep(nanoseconds: 1_400_000_000)
    withAnimation(.easeInOut(duration: 0.7)) {
      showMoon = true
    }
    try? await Task.sleep(nanoseconds: 500_000_000)
    withAnimation(.easeIn(duration: 1.3)) {
      landerY = -22
    }
  }
}
